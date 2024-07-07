
rule Trojan_Win32_Redline_GFP_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 03 8a 80 90 01 04 32 04 37 88 45 d3 ba 90 01 04 b9 90 01 04 e8 90 01 04 50 e8 90 01 04 59 0f b6 1c 37 90 00 } //10
		$a_03_1 = {8b c6 83 e0 03 8a 80 90 01 04 32 04 33 88 45 d3 ba 90 01 04 b9 90 01 04 e8 90 01 04 51 8b c8 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}