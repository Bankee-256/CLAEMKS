use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

use CLAEMKS::algs::*;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, black_box};

fn gen_key_words(n: usize) -> Vec<String> {
    let mut words = Vec::new();
    for _ in 0..n {
        let word: String = (0..10)
            .map(|_| {
                // 先把 (rand::random::<f32>() * 96.0) 转成 u8，再和 0x20u8 相加
                let c = 0x20u8 + ((rand::random::<f32>() * 96.0) as u8);
                // 再把结果转换成 char
                c as char
            })
            .collect();
        words.push(word);
    }
    words
}


fn bench_claemks(c: &mut Criterion){
    let mut group = c.benchmark_group("claemks");
    group.sample_size(10);
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

        // let W = ["Hello", "World", "Alice", "Bob", "Eve", "Malloy", "Trudy", "Oscar", "Charlie", "David", "Isaac", "Justin", "Peggy", "Steve", "Zoe"];

        let W = gen_key_words(100);
        let W = W.iter().map(|x| x.as_str()).collect::<Vec<&str>>();
        group.bench_function("claemks", |b| {
            b.iter(|| {
                CLAEMKS("Alice", "Bob", sk_do.clone(), pk_dr.clone(), Q_dr, P_pub, pk_cs, &W);
            });
        });

        let C = CLAEMKS
        ("Alice", "Bob", sk_do.clone(), pk_dr.clone(), Q_dr, P_pub, pk_cs, &W);

        group.bench_function("trapdoor", |b|{
            b.iter( || {
                Trap_door("Alice", "Bob", pk_do.clone(), sk_dr.clone(), pk_cs, Q_do, P_pub, &W);
            });
        });

        let T = Trap_door("Alice", "Bob", pk_do.clone(), sk_dr.clone(), pk_cs, Q_do, P_pub, &W);

        group.bench_function("test", |b|{
            b.iter( || {
                Test(sk_cs, C.clone(), T.clone(), W.len());
            });
        });


        group.finish();
}

criterion_group!(benches, bench_claemks);
criterion_main!(benches);
