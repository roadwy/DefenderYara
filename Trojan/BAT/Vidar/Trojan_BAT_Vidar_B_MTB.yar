
rule Trojan_BAT_Vidar_B_MTB{
	meta:
		description = "Trojan:BAT/Vidar.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {00 0a 00 06 18 6f ?? ?? 00 0a 00 06 18 6f ?? ?? 00 0a 00 06 6f ?? ?? 00 0a 0b 02 28 ?? ?? 00 0a 0c 07 08 16 08 8e 69 6f ?? ?? 00 0a 0d 09 } //2
		$a_03_1 = {00 0a 00 06 18 6f ?? ?? 00 0a 00 06 18 6f ?? ?? 00 0a 00 06 6f ?? ?? 00 0a 0b 07 02 16 02 8e 69 6f ?? ?? 00 0a 0c 08 28 ?? ?? 00 0a 0d de } //2
		$a_01_2 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //1 GetProcAddress
		$a_01_3 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //1 LoadLibrary
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}