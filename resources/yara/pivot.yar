import "pe"

rule test
{
  strings:
    $pivot = {c3}
  condition:
    $pivot in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}