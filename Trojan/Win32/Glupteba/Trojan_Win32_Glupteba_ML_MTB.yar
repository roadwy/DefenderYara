
rule Trojan_Win32_Glupteba_ML_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 10 33 df 33 cb 8d 44 24 28 89 4c 24 10 90 18 29 08 c3 } //1
		$a_02_1 = {8b 74 24 20 8b 6c 24 14 8b c6 8d 4c 24 1c 90 18 c1 e0 04 89 01 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}