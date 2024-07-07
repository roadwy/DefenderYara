
rule Trojan_Win32_Icedid_RPO_MTB{
	meta:
		description = "Trojan:Win32/Icedid.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c1 5a 8b 15 90 01 04 83 d2 00 a1 90 01 04 33 f6 2b c8 1b d6 a1 90 01 04 33 f6 03 c1 13 f2 90 00 } //1
		$a_03_1 = {83 c0 5a 8b c8 33 f6 2b 4d e8 1b 75 ec 0f b7 05 90 01 04 99 03 c1 13 d6 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}