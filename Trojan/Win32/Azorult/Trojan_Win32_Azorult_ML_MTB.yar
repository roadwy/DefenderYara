
rule Trojan_Win32_Azorult_ML_MTB{
	meta:
		description = "Trojan:Win32/Azorult.ML!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d e4 33 4d f0 89 4d e4 8b 55 e4 33 55 ec 89 55 e4 8b 45 d0 2b 45 e4 89 45 d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}