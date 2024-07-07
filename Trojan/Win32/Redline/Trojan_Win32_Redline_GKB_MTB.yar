
rule Trojan_Win32_Redline_GKB_MTB{
	meta:
		description = "Trojan:Win32/Redline.GKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 ca f6 d1 80 c1 75 32 ca 2a c1 b1 8b 32 c2 2a c8 2a ca 80 f1 0c 02 ca 32 ca 02 ca 32 ca 88 4c 14 18 42 83 fa 0f 72 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GKB_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c6 f7 74 24 90 01 01 68 90 01 04 68 90 01 04 8a ba 90 01 04 32 fb e8 90 01 04 8a 1c 3e 68 90 01 04 68 90 01 04 e8 90 01 04 83 c4 90 01 01 83 f8 90 01 01 75 90 01 01 2a fb 00 3c 3e 46 3b 74 24 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}