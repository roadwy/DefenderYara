
rule TrojanDropper_O97M_Abahk_YA_MTB{
	meta:
		description = "TrojanDropper:O97M/Abahk.YA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 41 75 74 6f 48 6f 74 6b 65 79 55 33 32 2e 65 78 65 } //1 C:\ProgramData\AutoHotkeyU32.exe
		$a_01_1 = {43 61 6c 6c 20 53 68 65 6c 6c 28 } //1 Call Shell(
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}