use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand_core::{OsRng};
use sha2::{Sha512, Digest};

#[derive(Clone)]
pub struct pk{
    pub X_u: RistrettoPoint,
    pub R_u: RistrettoPoint,
}

#[derive(Clone)]
pub struct sk{
    pub x_u: Scalar,
    pub d_u: Scalar,
}

#[derive(Clone)]
pub struct cipher_text{
    pub C_1: RistrettoPoint,
    pub C_2: Vec<Scalar>,
    pub C_3: String,
}

pub fn Setup() -> (RistrettoPoint, Scalar, RistrettoPoint, Scalar){
    let mut rng = OsRng;
    let s = Scalar::random(&mut rng);
    let P_pub = RISTRETTO_BASEPOINT_POINT * s;
    let sk_cs = Scalar::random(&mut rng);
    let pk_cs = RISTRETTO_BASEPOINT_POINT * sk_cs;
    (P_pub, sk_cs, pk_cs, s)
}

pub fn Extract_partical_private_key(s: Scalar, id: &str) -> (Scalar, RistrettoPoint, Scalar){
    let mut rng = OsRng;
    let r_u = Scalar::random(&mut rng);
    let R_u = RISTRETTO_BASEPOINT_POINT * r_u;
    let Q_u = h(id, R_u);
    let d_u = r_u + s * Q_u;
    (d_u, R_u, Q_u)
}

pub fn Set_secret_value() -> Scalar{
    let mut rng = OsRng;
    let x_u = Scalar::random(&mut rng);
    x_u
}

pub fn Set_public_key(x_u: Scalar, R_u: RistrettoPoint) -> (RistrettoPoint, RistrettoPoint){
    let X_u = RISTRETTO_BASEPOINT_POINT * x_u;
    (X_u, R_u)
}

pub fn CLAEMKS(ID_do: &str, ID_dr: &str, sk_do: sk, pk_dr:pk, Q_dr: Scalar, P_pub: RistrettoPoint, pk_cs: RistrettoPoint, W: &[&str]) -> cipher_text{
    let mut rng = OsRng;
    let r = Scalar::random(&mut rng);
    let k = Scalar::random(&mut rng);
    let C_1 = RISTRETTO_BASEPOINT_POINT * r;
    let K = sk_do.d_u * (pk_dr.R_u + Q_dr * P_pub);
    // println!("K c: {:?}", K.compress().as_bytes());
    let K_hat = sk_do.x_u * pk_dr.X_u;
    let mut b: Vec<Scalar> = Vec::new();
    for msg in W{
        let a_i = h_1(ID_do, ID_dr, msg, K, K_hat);
        // println!("a_i c: {:?}", a_i.to_bytes());
        let b_i = h_2(a_i * RISTRETTO_BASEPOINT_POINT, r * RISTRETTO_BASEPOINT_POINT, r * pk_cs);
        b.push(b_i);
    }
    let mut C_2 = polynomial_from_roots(&b);

    C_2[0] = C_2[0] + k;
    let C_3 = h_3(C_1, C_2.clone(), k);
    cipher_text{
        C_1: C_1,
        C_2: C_2,
        C_3: C_3,
    }
}

pub fn Trap_door(ID_do: &str, ID_dr: &str, pk_do: pk, sk_dr: sk, pk_cs: RistrettoPoint, Q_do: Scalar, P_pub: RistrettoPoint, W: &[&str] ) -> (Vec<RistrettoPoint>, Vec<RistrettoPoint>){
    let l = W.len();
    let mut rng = OsRng;
    let S: Vec<Scalar> = (0..l).map(|_| Scalar::random(&mut rng)).collect();
    let K = sk_dr.d_u * (pk_do.R_u + Q_do * P_pub);
    // println!("K t: {:?}", K.compress().as_bytes());
    let K_hat  = sk_dr.x_u * pk_do.X_u;
    let mut T_1: Vec<RistrettoPoint> = Vec::new();
    let mut T_2: Vec<RistrettoPoint> = Vec::new();
    for i in 0..l{
        let a_i = h_1(ID_do, ID_dr, W[i], K, K_hat);
        // println!("a_i t: {:?}", a_i.to_bytes());
        let c_i = h_4(S[i] * RISTRETTO_BASEPOINT_POINT, S[i] * pk_cs);
        let T_1_i = S[i] * RISTRETTO_BASEPOINT_POINT;
        let T_2_i = a_i * c_i * RISTRETTO_BASEPOINT_POINT;
        T_1.push(T_1_i);
        T_2.push(T_2_i);
    }

    (T_1, T_2)
}

fn polynomial_from_roots(roots: &[Scalar]) -> Vec<Scalar> {
    let mut coeffs = vec![Scalar::ONE]; 
    for &r in roots {
        let n = coeffs.len();
        let mut new_coeffs = vec![Scalar::ZERO; n + 1];
        // 先更新新系数
        for i in (0..n).rev() {
            new_coeffs[i + 1] = new_coeffs[i + 1] + coeffs[i];        // x * coeffs[i]
            new_coeffs[i]     = new_coeffs[i]     - (r * coeffs[i]); // -r * coeffs[i]
        }
        coeffs = new_coeffs;
    }
    coeffs
}

fn eval_poly_from_coeffs(coeffs: &[Scalar], x: Scalar) -> Scalar {
    coeffs.iter().rev().fold(Scalar::ZERO, |acc, &c| acc * x + c)
}

fn eval_poly_from_coeffs_i32(coeffs: &[i32], x: i32) -> i32 {
    coeffs.iter().rev().fold(0, |acc, &c| acc * x + c)
}


pub fn Test(sk_cs: Scalar, C: cipher_text, T: (Vec<RistrettoPoint>, Vec<RistrettoPoint>), l:usize){
    let C_1_prime = C.C_1 * sk_cs;
    let mut T_1_prime: Vec<RistrettoPoint> = Vec::new();
    let mut T_2_prime: Vec<RistrettoPoint> = Vec::new();
    for i in 0..l{
        let T_1_i_prime = T.0[i] * sk_cs;
        let T_2_i_prime = h_4(T.0[i] , T_1_i_prime).invert() * T.1[i];
        T_1_prime.push(T_1_i_prime);
        T_2_prime.push(T_2_i_prime);
        let b_i_prime = h_2(T_2_i_prime, C.C_1, C_1_prime);
        let k_prime = eval_poly_from_coeffs(&C.C_2, b_i_prime);
        if C.C_3 == h_3(C.C_1, C.C_2.clone(), k_prime){
            // println!("The ciphertext is valid");
        }
        else{
            // println!("The ciphertext is invalid");
        }
    }
}

fn polynomial_from_roots_i32(roots: &[i32]) -> Vec<i32> {
    let mut coeffs = vec![1]; // 1表示x^0的系数
    for &r in roots {
        let n = coeffs.len();
        let mut new_coeffs = vec![0; n + 1];
        // 先更新新系数
        for i in (0..n).rev() {
            new_coeffs[i + 1] = new_coeffs[i + 1] + coeffs[i];        // x * coeffs[i]
            new_coeffs[i]     = new_coeffs[i]     - (r * coeffs[i]); // -r * coeffs[i]
        }
        coeffs = new_coeffs;
    }
    coeffs
}

pub fn h(input_str: &str, R: RistrettoPoint) -> Scalar {
    let compressed = R.compress();
    let mut hasher = Sha512::new();
    hasher.update(input_str.as_bytes());
    hasher.update(compressed.as_bytes());
    Scalar::from_hash(hasher)
}

pub fn h_1(input_str_1: &str, input_str_2: &str, input_str_3: &str, R_1: RistrettoPoint, R_2: RistrettoPoint) -> Scalar {
    let compressed_1 = R_1.compress();
    let compressed_2 = R_2.compress();
    let mut hasher = Sha512::new();
    hasher.update(input_str_1.as_bytes());
    hasher.update(input_str_2.as_bytes());
    hasher.update(input_str_3.as_bytes());
    hasher.update(compressed_1.as_bytes());
    hasher.update(compressed_2.as_bytes());
    Scalar::from_hash(hasher)
}

pub fn h_2(R_1: RistrettoPoint, R_2: RistrettoPoint, R_3: RistrettoPoint) -> Scalar {
    let compressed_1 = R_1.compress();
    let compressed_2 = R_2.compress();
    let compressed_3 = R_3.compress();
    let mut hasher = Sha512::new();
    hasher.update(compressed_1.as_bytes());
    hasher.update(compressed_2.as_bytes());
    hasher.update(compressed_3.as_bytes());
    Scalar::from_hash(hasher)
}

pub fn h_3(r: RistrettoPoint, v: Vec<Scalar>, s: Scalar) -> String{
    let compressed = r.compress();
    let mut hasher = Sha512::new();
    hasher.update(compressed.as_bytes());
    for i in v{
        hasher.update(i.as_bytes());
    }
    hasher.update(s.as_bytes());
    // Scalar::from_hash(hasher)
    // output string
    let result = hasher.finalize();
    let result_str = format!("{:x}", result);
    result_str
}

pub fn h_4(r_1: RistrettoPoint, r_2: RistrettoPoint) -> Scalar{
    let compressed_1 = r_1.compress();
    let compressed_2 = r_2.compress();
    let mut hasher = Sha512::new();
    hasher.update(compressed_1.as_bytes());
    hasher.update(compressed_2.as_bytes());
    Scalar::from_hash(hasher)
}

#[cfg(test)]
mod test{
    use super::*;
    #[test]
    fn test_correctness(){
        let (P_pub, sk_cs, pk_cs, s) = Setup();
        let x_do = Set_secret_value();
        let x_dr = Set_secret_value();
        let (d_do, R_do, Q_do) = Extract_partical_private_key(s, "Alice");
        let (d_dr, R_dr, Q_dr) = Extract_partical_private_key(s, "Bob");
        let (X_do, R_do) = Set_public_key(x_do, R_do);
        let (X_dr, R_dr) = Set_public_key(x_dr, R_dr);
        let pk_do = pk{
            X_u: X_do,
            R_u: R_do,
        };
        let pk_dr = pk{
            X_u: X_dr,
            R_u: R_dr,
        };
        let sk_do = sk{
            x_u: x_do,
            d_u: d_do,
        };
        let sk_dr = sk{
            x_u: x_dr,
            d_u: d_dr,
        };


        let W = ["Hello", "World", "Alice", "Bob", "Eve", "Mallory", "Trudy", "Oscar", "Charlie", "David"];
        // let W = ["Hello"];
        let C = CLAEMKS("Alice", "Bob", sk_do, pk_dr, Q_dr, P_pub, pk_cs, &W);
        let T = Trap_door("Alice", "Bob", pk_do, sk_dr, pk_cs, Q_do, P_pub, &W);
        Test(sk_cs, C, T, W.len());
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_polynomial_from_roots() {
//         // Test case 1: One root
//         let roots = vec![3];
//         let result = polynomial_from_roots(&roots);
//         assert_eq!(result, vec![-3, 1]);  // P(x) = x - 3, 系数应该是 [1, -3]

//         // Test case 2: Two roots
//         let roots = vec![1, -2];
//         let result = polynomial_from_roots(&roots);
//         assert_eq!(result, vec![-2, 1, 1]);  // P(x) = (x - 1)(x + 2), 系数应该是 [1, 1, -2]

//         // Test case 3: Three roots
//         let roots = vec![1, -1, 2];
//         let result = polynomial_from_roots(&roots);
//         assert_eq!(result, vec![2, -1, -2, 1]);  // P(x) = (x - 1)(x + 1)(x - 2), 系数应该是 [1, -2, -1, 2]
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_eval_poly_from_coeffs() {
//         // Test case 1: Polynomial P(x) = x^2 + x - 2, coefficients are [1, 1, -2]
//         let coeffs = vec![-2, 1, 1]; // P(x) = x^2 + x - 2
//         let x = 2;
//         let result = eval_poly_from_coeffs_i32(&coeffs, x);
//         assert_eq!(result, 4); // P(2) = 2^2 + 2 - 2 = 4

//         // Test case 2: Polynomial P(x) = x^2 + 3x + 2, coefficients are [2, 3, 1]
//         let coeffs = vec![2, 3, 1]; // P(x) = x^2 + 3x + 2
//         let x = 1;
//         let result = eval_poly_from_coeffs_i32(&coeffs, x);
//         assert_eq!(result, 6); // P(1) = 1^2 + 3*1 + 2 = 6

//         // Test case 3: Polynomial P(x) = x - 3, coefficients are [-3, 1]
//         let coeffs = vec![-3, 1]; // P(x) = x - 3
//         let x = 3;
//         let result = eval_poly_from_coeffs_i32(&coeffs, x);
//         assert_eq!(result, 0); // P(3) = 3 - 3 = 0

//         // Test case 4: Polynomial P(x) = -x^2 + 4x + 5, coefficients are [5, 4, -1]
//         let coeffs = vec![5, 4, -1]; // P(x) = -x^2 + 4x + 5
//         let x = -1;
//         let result = eval_poly_from_coeffs_i32(&coeffs, x);
//         assert_eq!(result, 00); // P(-1) = -(-1)^2 + 4*(-1) + 5 = 0
//     }
// }