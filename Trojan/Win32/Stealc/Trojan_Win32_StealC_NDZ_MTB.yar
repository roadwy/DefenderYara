
rule Trojan_Win32_StealC_NDZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.NDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {30 04 0a 83 bc 24 24 08 00 00 90 01 01 75 90 0a 14 00 8b 54 24 90 01 01 8b 4c 24 90 00 } //01 00 
		$a_03_1 = {8b 0d e8 f9 52 00 69 c9 fd 43 03 00 81 c1 90 01 04 89 0d e8 f9 52 00 0f b7 05 ea f9 52 00 8b 8c 24 00 08 00 00 33 cc 25 ff 7f 00 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}