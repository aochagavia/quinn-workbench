pub mod serde_arc_str {
    use serde::de::{Error, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt::Formatter;
    use std::sync::Arc;

    pub fn serialize<S>(s: &Arc<str>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Arc<str>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArcStrVisitor;
        impl Visitor<'_> for ArcStrVisitor {
            type Value = Arc<str>;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                self.visit_string(v.to_string())
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(v.into_boxed_str().into())
            }
        }

        deserializer.deserialize_string(ArcStrVisitor)
    }
}
