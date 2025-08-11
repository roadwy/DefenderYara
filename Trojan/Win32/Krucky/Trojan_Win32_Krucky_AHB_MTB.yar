
rule Trojan_Win32_Krucky_AHB_MTB{
	meta:
		description = "Trojan:Win32/Krucky.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {b9 19 00 00 00 33 c0 8a 90 90 ?? ?? ?? ?? 32 d1 41 81 e1 ff 00 00 80 88 54 05 e4 79 ?? 49 81 c9 00 ff ff ff 41 40 83 f8 0c 7c } //10
		$a_03_1 = {89 45 d4 89 45 d8 89 45 dc 88 45 e0 89 45 e4 89 45 e8 89 45 ec 88 45 f0 a1 ?? ?? ?? ?? 8b 11 8b 52 08 05 b8 00 00 00 50 ff d2 } //5
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*5) >=15
 
}