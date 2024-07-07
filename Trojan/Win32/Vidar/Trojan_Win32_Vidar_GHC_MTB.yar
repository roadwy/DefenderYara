
rule Trojan_Win32_Vidar_GHC_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 33 d2 8b c7 f7 f1 8b 85 90 01 04 8a 0c 02 8b 95 90 01 04 32 0c 1a 8d 85 90 01 04 50 88 0b ff d6 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}