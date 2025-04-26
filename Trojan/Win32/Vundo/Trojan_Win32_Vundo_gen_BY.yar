
rule Trojan_Win32_Vundo_gen_BY{
	meta:
		description = "Trojan:Win32/Vundo.gen!BY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 b6 1f 00 00 e8 ?? ?? ?? ?? 66 89 45 ?? 6a 00 6a 01 6a 02 } //1
		$a_03_1 = {8d 14 81 89 55 ?? 8b 45 ?? 8b 08 89 4d ?? 8b 55 ?? 33 55 ?? 8b 45 ?? 33 10 } //1
		$a_01_2 = {78 32 5f 73 68 61 72 65 64 } //1 x2_shared
		$a_01_3 = {78 32 2e 64 6c 6c 00 69 6e 73 74 61 6c 6c 00 70 6f 70 75 70 } //1 ㉸搮汬椀獮慴汬瀀灯灵
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}