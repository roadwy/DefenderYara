
rule TrojanDropper_Win32_VB_EL{
	meta:
		description = "TrojanDropper:Win32/VB.EL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {42 00 65 00 73 00 69 00 74 00 7a 00 65 00 72 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 63 00 61 00 72 00 62 00 6f 00 6e 00 61 00 61 00 61 00 61 00 } //1 Besitzer\Desktop\carbonaaaa
		$a_01_1 = {43 61 6c 6c 41 50 49 62 79 4e 61 6d 65 00 00 00 53 74 61 72 74 00 00 00 52 75 6e 50 45 00 00 00 52 43 34 00 46 6f 72 6d 31 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}