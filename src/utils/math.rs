/// Compute the inner product of two vectors.
pub fn dot(u: &[f64], v: &[f64]) -> f64 {
    u.iter().zip(v.iter()).map(|(x, y)| (x * y)).sum()
}

/// Compute the L1-norm of a vector.
pub fn l1_norm(v: &[f64]) -> f64 {
    v.iter().map(|x| x.abs()).sum()
}

/// Compute the L2-norm of a vector.
pub fn l2_norm(v: &[f64]) -> f64 {
    v.iter().map(|x| x.powi(2)).sum::<f64>().sqrt()
}

/// Normalize a vector using the L1 norm.
pub fn l1_normalize(v: &[f64]) -> Vec<f64> {
    let v_norm = l1_norm(&v);
    v.iter().map(|x| x / v_norm).collect()
}

/// Normalize a vector using the L2 norm.
pub fn l2_normalize(v: &[f64]) -> Vec<f64> {
    let v_norm = l2_norm(&v);
    v.iter().map(|x| x / v_norm).collect()
}

/// Compute the L1 (Manhattan) distance between two vectors.
pub fn l1_dist(u: &[f64], v: &[f64]) -> f64 {
    u.iter().zip(v.iter()).map(|(x, y)| (x - y).abs()).sum()
}

/// Compute the L2 (Euclidean) distance between two vectors.
pub fn l2_dist(u: &[f64], v: &[f64]) -> f64 {
    u.iter().zip(v.iter()).map(|(x, y)| (x - y).powi(2)).sum::<f64>().sqrt()
}

/// Compute the normalized L1 similarity between two vectors.
pub fn l1_sim(u: &[f64], v: &[f64]) -> f64 {
    1.0 - l1_dist(&l1_normalize(&u), &l1_normalize(&v))
}

/// Compute the normalized L2 similarity between two vectors.
pub fn l2_sim(u: &[f64], v: &[f64]) -> f64 {
    1.0 - l2_dist(&l2_normalize(&u), &l2_normalize(&v))
}

/// Compute the cosine similarity of two vectors.
pub fn cosine_sim(u: &[f64], v: &[f64]) -> f64 {
    dot(&u, &v) / (l2_norm(&u) * l2_norm(&v))
}
