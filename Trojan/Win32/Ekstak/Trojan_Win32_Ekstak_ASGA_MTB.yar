
rule Trojan_Win32_Ekstak_ASGA_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 ff d3 68 90 01 03 00 56 a3 90 01 03 00 ff d3 57 a3 90 01 03 00 ff 15 90 01 03 00 f7 d8 1b c0 5f 5e 5b f7 d8 c3 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}