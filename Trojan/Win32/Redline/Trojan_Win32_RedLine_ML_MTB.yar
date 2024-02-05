
rule Trojan_Win32_RedLine_ML_MTB{
	meta:
		description = "Trojan:Win32/RedLine.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {89 c8 ba 00 00 00 00 f7 f5 c1 ea 02 b8 68 00 00 00 f6 24 17 30 04 0b 83 c1 01 39 ce 75 } //00 00 
	condition:
		any of ($a_*)
 
}