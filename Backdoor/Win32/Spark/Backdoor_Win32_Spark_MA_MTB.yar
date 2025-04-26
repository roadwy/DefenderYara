
rule Backdoor_Win32_Spark_MA_MTB{
	meta:
		description = "Backdoor:Win32/Spark.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {18 12 8e e1 b8 3b 21 e7 10 3a 89 e1 38 c2 b7 57 cb 9a b5 3a 93 c9 64 30 32 3a 88 e1 b7 3b 89 e1 } //1
		$a_01_1 = {b7 3b 4b 20 a0 3a 89 e1 b8 e3 7b 1b b8 3b 89 1c b8 eb 44 e0 eb 38 30 ad d1 e5 30 65 7b ce 30 2b } //1
		$a_01_2 = {e0 00 02 01 0b 01 0e 10 00 ee 07 00 00 aa 06 00 00 00 00 00 00 90 54 00 00 10 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}