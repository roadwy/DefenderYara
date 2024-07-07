
rule Trojan_Win32_Redline_GHC_MTB{
	meta:
		description = "Trojan:Win32/Redline.GHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 03 8a 88 90 01 04 32 0c 33 0f b6 1c 33 8d 04 19 8b 4d b4 88 04 31 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}