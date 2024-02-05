use regex::Regex;

use super::annotation_kind::ZAlpha;

pub fn extract_z_and_alpha(annotations: &[&str]) -> anyhow::Result<ZAlpha> {
    let re = Regex::new(
        r"V->P: /cpu air/STARK/Interaction: Interaction element #\d+: Field Element\(0x([0-9a-f]+)\)",
    ).unwrap();

    let mut interaction_elements = Vec::new();

    for annotation in annotations {
        for cap in re.captures_iter(annotation) {
            let value = u32::from_str_radix(&cap[1], 16)?;
            interaction_elements.push(value);
        }
    }

    // Make sure the number of interaction_elements is as expected
    if ![3, 6].contains(&interaction_elements.len()) {
        anyhow::bail!(
            "Unexpected number of interaction elements: {}",
            interaction_elements.len()
        );
    }

    let z_alpha = ZAlpha {
        z: interaction_elements[0],
        alpha: interaction_elements[1],
    };

    Ok(z_alpha)
}

pub fn extract_annotations(annotations: &[&str], prefix: &str, kind: &str) -> Vec<u32> {
    let pattern = format!(r"P->V\[(\d+):(\d+)\]: /cpu air/{}: .*{}\\((.+)\\)", regex::escape(prefix), kind);
    let re = Regex::new(&pattern).unwrap();
    let mut res: Vec<u32> = Vec::new();

    for line in annotations {
        if let Some(cap) = re.captures(line) {
            let str_value = &cap[3];
            if kind == "Field Elements" {
                res.extend(str_value.split(",").filter_map(|x| u32::from_str_radix(x, 16).ok()));
            } else {
                if let Ok(value) = u32::from_str_radix(str_value, 16) {
                    res.push(value);
                }
            }
        }
    }

    res
}
