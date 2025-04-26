
rule Backdoor_BAT_Remcos_SPJ_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 6b 74 65 6c 6c 65 5f 44 6f 77 6e 6c 6f 61 64 73 } //1 Aktelle_Downloads
		$a_01_1 = {41 6b 74 75 65 6c 6c 65 5f 53 61 6d 6d 6c 75 6e 67 } //1 Aktuelle_Sammlung
		$a_01_2 = {5f 6b 6c 61 6d 6d 65 72 6e 5f 69 67 6e 6f 72 69 65 72 65 6e } //1 _klammern_ignorieren
		$a_01_3 = {5f 48 65 61 64 65 72 5f 64 6c 6c 69 6e 6b } //1 _Header_dllink
		$a_01_4 = {5f 64 6f 6e 6f 74 63 6c 65 61 6e 75 70 } //1 _donotcleanup
		$a_01_5 = {63 68 5f 73 61 6d 70 72 61 74 65 } //1 ch_samprate
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}