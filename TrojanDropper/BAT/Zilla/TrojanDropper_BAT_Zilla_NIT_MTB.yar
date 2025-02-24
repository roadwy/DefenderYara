
rule TrojanDropper_BAT_Zilla_NIT_MTB{
	meta:
		description = "TrojanDropper:BAT/Zilla.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6f 3c 00 00 0a 6f 3d 00 00 0a 6f 3e 00 00 0a 06 18 6f 3f 00 00 0a 06 6f 40 00 00 0a 13 04 02 0d 11 04 09 16 09 8e b7 6f 41 00 00 0a 0b } //2
		$a_00_1 = {63 00 78 00 72 00 73 00 6c 00 64 00 67 00 } //1 cxrsldg
		$a_00_2 = {25 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 25 00 } //1 %AppData%
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}