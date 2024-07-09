
rule Trojan_Win32_Xpack_RPY_MTB{
	meta:
		description = "Trojan:Win32/Xpack.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {51 b9 0a 00 00 00 8b 04 9e f7 f1 88 15 ?? ?? ?? ?? 89 04 9f 4b 59 49 75 e7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Xpack_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Xpack.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c2 81 c2 ff 00 00 00 89 c6 81 e6 1f 00 00 00 8a 1c 31 8b 4d f0 8a 3c 01 28 df 88 3c 01 8b 45 f4 39 c2 89 55 e4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}