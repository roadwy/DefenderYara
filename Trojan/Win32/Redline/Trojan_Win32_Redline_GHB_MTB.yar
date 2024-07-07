
rule Trojan_Win32_Redline_GHB_MTB{
	meta:
		description = "Trojan:Win32/Redline.GHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 2e 8b c6 83 e0 03 ba 90 01 04 b9 90 01 04 8a 80 90 01 04 32 c3 02 c3 88 04 90 00 } //10
		$a_03_1 = {8a 1c 2e 8b c6 83 e0 03 ba 90 01 04 8a 80 90 01 04 32 c3 02 c3 88 04 2e 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}