
rule Trojan_Win32_Emotet_VAV_MTB{
	meta:
		description = "Trojan:Win32/Emotet.VAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 d1 89 c8 99 f7 fe 8b 4d ?? 8a 3c 11 81 f7 50 27 e3 75 8b 75 c0 88 3c 31 88 1c 11 0f b6 0c 31 8b 75 c4 } //3
		$a_03_1 = {8a 1c 0f 8b 4d e4 8b 75 cc 32 1c 31 8b 4d ec 81 f1 ae 27 e3 75 8b 75 e0 8b 7d cc 88 1c 3e 01 cf 8b 4d ?? 39 cf 8b 4d c0 89 4d d0 89 7d d4 89 55 d8 0f 84 51 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}