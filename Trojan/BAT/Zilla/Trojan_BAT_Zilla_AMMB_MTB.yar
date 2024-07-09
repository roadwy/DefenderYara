
rule Trojan_BAT_Zilla_AMMB_MTB{
	meta:
		description = "Trojan:BAT/Zilla.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 00 02 1a 18 73 ?? 00 00 0a 13 06 11 06 ?? 11 05 28 08 00 00 06 00 11 06 6f ?? 00 00 0a 00 16 13 07 2b 00 11 07 2a } //2
		$a_03_1 = {0a 16 9a 0a 06 6f ?? 00 00 0a 1a 17 73 ?? 00 00 0a 0b 07 20 ?? ?? ?? ?? 16 28 ?? 00 00 06 0c 07 6f ?? 00 00 0a 00 02 1a 17 73 ?? 00 00 0a 0d 09 6f ?? 00 00 0a 69 } //2
		$a_01_2 = {46 69 6c 65 49 6e 66 65 63 74 6f 72 } //1 FileInfector
		$a_01_3 = {47 65 74 44 69 72 65 63 74 6f 72 69 65 73 } //1 GetDirectories
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}