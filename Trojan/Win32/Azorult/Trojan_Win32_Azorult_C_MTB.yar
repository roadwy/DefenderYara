
rule Trojan_Win32_Azorult_C_MTB{
	meta:
		description = "Trojan:Win32/Azorult.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 75 ?? 8b 45 ?? 0f b6 0c 10 8b 55 ?? 03 55 ?? 0f b6 02 33 c1 8b 4d ?? 03 4d ?? 88 01 } //2
		$a_03_1 = {0f b7 45 ec 6b c8 ?? 8b 55 e8 8b 44 0a } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}