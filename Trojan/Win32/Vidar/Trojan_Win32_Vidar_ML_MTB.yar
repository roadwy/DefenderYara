
rule Trojan_Win32_Vidar_ML_MTB{
	meta:
		description = "Trojan:Win32/Vidar.ML!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 8b d0 c1 e9 05 03 4c 24 34 c1 e2 04 03 d5 33 ca 8b 54 24 14 03 d0 33 ca 2b f9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}