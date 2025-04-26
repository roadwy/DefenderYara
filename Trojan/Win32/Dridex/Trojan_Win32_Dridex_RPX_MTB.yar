
rule Trojan_Win32_Dridex_RPX_MTB{
	meta:
		description = "Trojan:Win32/Dridex.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 e0 89 45 b0 8d 45 d8 89 45 ac 8b 45 b0 89 4d a8 8b 4d ac 89 48 0c 89 58 04 8b 4d a8 89 08 c7 40 08 04 00 00 00 89 7d a4 89 55 a0 89 75 9c ff d2 } //1
		$a_01_1 = {8b 4d ec 8b 55 e0 8a 3c 11 28 df 8b 75 e8 88 3c 16 81 c2 01 00 00 00 8b 7d f0 39 fa 89 55 e4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}