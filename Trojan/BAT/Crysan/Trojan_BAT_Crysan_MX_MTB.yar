
rule Trojan_BAT_Crysan_MX_MTB{
	meta:
		description = "Trojan:BAT/Crysan.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_02_0 = {11 0b 11 08 6f ?? 00 00 0a 26 } //2
		$a_00_1 = {09 7e 0d 00 00 04 28 16 00 00 06 13 05 } //2
		$a_80_2 = {70 6f 6c 61 74 66 61 6d 69 6c 79 65 6e 67 69 6e 65 } //polatfamilyengine  3
		$a_00_3 = {42 6c 6f 63 6b 43 6f 70 79 } //1 BlockCopy
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2+(#a_80_2  & 1)*3+(#a_00_3  & 1)*1) >=6
 
}