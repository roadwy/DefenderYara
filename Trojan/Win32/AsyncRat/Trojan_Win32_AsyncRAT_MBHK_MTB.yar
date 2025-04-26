
rule Trojan_Win32_AsyncRAT_MBHK_MTB{
	meta:
		description = "Trojan:Win32/AsyncRAT.MBHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 a0 c1 e0 06 8b 4d a0 8b 55 dc 89 04 8a 8b 45 a0 c1 e0 0c 8b 4d a0 8b 55 b4 89 04 8a 8b 45 a0 c1 e0 12 } //1
		$a_01_1 = {60 18 40 00 10 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 80 16 40 00 00 16 40 00 c4 14 40 00 78 00 00 00 7f 00 00 00 86 00 00 00 87 } //1
		$a_01_2 = {42 42 f6 57 df 42 00 42 42 f6 57 df 42 00 00 42 42 f6 57 df 42 00 00 00 01 00 00 00 f4 1c 40 00 00 00 00 00 2c 27 40 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}