
rule Trojan_Win32_Azorult_BQ_MTB{
	meta:
		description = "Trojan:Win32/Azorult.BQ!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 4d a8 d3 ea 89 55 ec 8b 45 ec 03 45 d4 89 45 ec 8b 4d e4 33 4d f0 89 4d e4 8b 45 ec 31 45 e4 8b 55 d0 2b 55 e4 89 55 d0 } //00 00 
	condition:
		any of ($a_*)
 
}