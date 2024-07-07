
rule Trojan_BAT_Sabsik_FTR_MTB{
	meta:
		description = "Trojan:BAT/Sabsik.FTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {1f 20 20 00 80 00 00 73 4b 00 00 0a 0b 04 14 14 07 20 00 80 00 00 03 28 25 00 00 06 26 07 17 8d 76 00 00 01 6f 4c 00 00 0a 73 4d 00 00 0a 0c 08 08 6f 4e 00 00 0a 18 da 18 6f 4f 00 00 0a 00 08 0a 2b 00 06 2a } //10
		$a_80_1 = {4d 65 73 73 61 67 65 53 75 72 72 6f 67 61 74 65 46 69 6c 74 65 72 } //MessageSurrogateFilter  3
		$a_80_2 = {4c 4f 47 4f } //LOGO  3
		$a_80_3 = {47 65 74 4b 65 79 73 } //GetKeys  3
		$a_80_4 = {49 4e 49 46 69 6c 65 73 } //INIFiles  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}