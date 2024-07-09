
rule Trojan_Win32_Piptea_E{
	meta:
		description = "Trojan:Win32/Piptea.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 10 6a 00 8d 45 ?? 50 8d 45 ?? 50 ff 15 ?? ?? ?? ?? 85 c0 75 } //1
		$a_03_1 = {b9 79 37 9e 90 09 03 00 c7 45 } //1
		$a_03_2 = {0f b6 40 02 85 c0 74 ?? e9 } //1
		$a_03_3 = {03 48 28 89 4d ?? ff 55 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}