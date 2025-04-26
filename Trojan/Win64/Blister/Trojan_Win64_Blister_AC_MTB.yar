
rule Trojan_Win64_Blister_AC_MTB{
	meta:
		description = "Trojan:Win64/Blister.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 17 83 e3 07 48 83 c7 04 8b ca 8b c2 41 23 cb 41 0b c3 f7 d1 23 c8 41 2b c8 44 8b c2 89 0e 8b cb 48 83 c6 04 41 d3 c0 ff c3 49 83 e9 01 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}