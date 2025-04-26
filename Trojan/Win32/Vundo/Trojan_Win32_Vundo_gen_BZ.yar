
rule Trojan_Win32_Vundo_gen_BZ{
	meta:
		description = "Trojan:Win32/Vundo.gen!BZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {8d 04 8a 89 45 ?? 8b 4d ?? 8b 11 89 55 ?? 8b 45 ?? 33 45 ?? 8b 4d ?? 33 01 } //1
		$a_03_1 = {75 1a 8d 95 e8 fd ff ff 52 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 } //1
		$a_03_2 = {6a 3f 8b 85 6c f3 ff ff 50 ff 15 ?? ?? ?? ?? 85 c0 75 0c c7 85 ?? ?? ?? ?? ?? ?? ?? ?? eb 0a } //1
		$a_01_3 = {78 32 5f 61 6c 69 76 65 5f 6d 75 74 65 78 } //1 x2_alive_mutex
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}