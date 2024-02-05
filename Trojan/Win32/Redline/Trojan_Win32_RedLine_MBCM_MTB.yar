
rule Trojan_Win32_RedLine_MBCM_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MBCM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 74 24 10 8b 44 24 14 31 44 24 10 2b 7c 24 10 81 3d 90 01 04 93 00 00 00 75 90 00 } //01 00 
		$a_03_1 = {c1 e8 05 8d 34 2b c7 05 90 01 04 19 36 6b ff c7 05 90 01 04 ff ff ff ff 89 44 24 14 8b 44 24 20 01 44 24 14 81 3d 90 01 04 79 09 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}