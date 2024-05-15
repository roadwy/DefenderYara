
rule Trojan_Win32_Redline_ML_MTB{
	meta:
		description = "Trojan:Win32/Redline.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f6 17 80 07 90 01 01 b8 df 00 00 00 80 2f 90 01 01 f6 2f 47 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_ML_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {89 c8 ba 00 00 00 00 f7 f5 c1 ea 02 b8 68 00 00 00 f6 24 17 30 04 0b 83 c1 01 39 ce 75 } //00 00 
	condition:
		any of ($a_*)
 
}