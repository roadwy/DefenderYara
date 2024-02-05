
rule Trojan_Win32_Totbrick_AD_MTB{
	meta:
		description = "Trojan:Win32/Totbrick.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c8 2b ce 01 4c 24 90 01 01 8d 4c 3b 90 01 01 66 89 0d 90 01 04 8b 4c 24 14 8b 09 89 0d 90 01 04 0f b7 4c 24 10 bd 90 01 04 8d bc 0f 90 01 04 3b f5 75 90 00 } //01 00 
		$a_02_1 = {8b 44 24 14 8b 15 90 01 04 89 10 a1 90 01 04 0f af 05 90 01 04 3d 90 01 04 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}