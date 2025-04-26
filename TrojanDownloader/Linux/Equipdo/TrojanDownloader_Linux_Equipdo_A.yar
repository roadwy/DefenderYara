
rule TrojanDownloader_Linux_Equipdo_A{
	meta:
		description = "TrojanDownloader:Linux/Equipdo.A,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 68 65 6c 6c 45 63 73 65 63 75 74 65 } //1 ChellEcsecute
		$a_01_1 = {4d 73 67 42 6f 78 20 22 45 73 74 65 20 64 6f 63 75 6d 65 6e 74 6f 20 6e 6f 20 65 73 20 63 6f 6d 70 61 74 69 62 6c 65 20 63 6f 6e 20 65 73 74 65 } //1 MsgBox "Este documento no es compatible con este
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}