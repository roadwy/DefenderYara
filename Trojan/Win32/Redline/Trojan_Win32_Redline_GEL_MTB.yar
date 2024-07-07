
rule Trojan_Win32_Redline_GEL_MTB{
	meta:
		description = "Trojan:Win32/Redline.GEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 2e ba 90 01 04 e8 90 01 04 50 e8 90 01 04 8b c6 ba 90 01 04 83 e0 03 59 8a b8 90 01 04 32 fb 8a 1c 2e e8 90 01 04 50 e8 90 01 04 2a fb 00 3c 2e 46 59 3b f7 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}