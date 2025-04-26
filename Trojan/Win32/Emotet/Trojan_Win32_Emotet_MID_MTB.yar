
rule Trojan_Win32_Emotet_MID_MTB{
	meta:
		description = "Trojan:Win32/Emotet.MID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d ec 8b 55 ec 81 f2 42 e4 dc 3e 8b 75 bc 8b 7d bc 8b 5d bc 89 75 ac 66 8b 75 f2 66 81 f6 91 36 89 45 a8 a1 ?? ?? ?? ?? 89 45 a4 8b 45 cc 89 45 a0 8a 45 f1 04 a0 88 45 9f 8b 45 a8 } //5
		$a_03_1 = {21 cf 8b 4d 94 81 f1 43 e4 dc 3e 89 4d 8c 8b 4d a0 89 55 88 8b 55 8c 39 d1 8b 4d 88 0f 47 f9 8a 4d 9f 8b 55 a4 2a 0c 3a 66 8b 7d ?? 8b 55 b4 02 0c 1a 88 4d e7 66 39 f7 0f 85 } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}