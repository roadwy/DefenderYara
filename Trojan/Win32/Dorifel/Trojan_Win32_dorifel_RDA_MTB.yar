
rule Trojan_Win32_dorifel_RDA_MTB{
	meta:
		description = "Trojan:Win32/dorifel.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 0e 84 c9 74 ?? 6a 01 83 e9 41 58 d3 e0 56 33 f8 ff 15 ?? ?? ?? ?? 8d 74 06 01 eb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}