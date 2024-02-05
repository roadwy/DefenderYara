
rule Backdoor_BAT_CrimsonRat_E_MTB{
	meta:
		description = "Backdoor:BAT/CrimsonRat.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 0e 00 00 0a 00 "
		
	strings :
		$a_02_0 = {4c 00 45 00 5f 00 41 00 55 00 90 02 02 54 00 4f 00 3c 00 21 00 90 0a 1e 00 3c 00 46 00 49 00 90 00 } //0a 00 
		$a_02_1 = {4c 45 5f 41 55 90 02 02 54 4f 3c 21 90 0a 1e 00 3c 46 49 90 00 } //05 00 
		$a_80_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //SOFTWARE\Microsoft\Windows\CurrentVersion\Run  01 00 
		$a_80_3 = {24 6b 65 65 72 75 6e } //$keerun  01 00 
		$a_80_4 = {24 75 73 62 77 72 6d } //$usbwrm  01 00 
		$a_80_5 = {2e 70 64 62 } //.pdb  01 00 
		$a_80_6 = {24 67 65 74 61 76 73 } //$getavs  01 00 
		$a_80_7 = {24 63 6c 72 6b 6c 67 } //$clrklg  01 00 
		$a_80_8 = {24 63 6c 70 69 6e 67 } //$clping  01 00 
		$a_80_9 = {24 75 73 62 72 75 6e } //$usbrun  01 00 
		$a_80_10 = {24 70 61 73 73 6c } //$passl  01 00 
		$a_02_11 = {72 00 65 00 63 00 6f 00 76 00 65 00 90 02 0f 7c 00 90 00 } //01 00 
		$a_02_12 = {72 65 63 6f 76 65 90 02 0f 7c 90 00 } //01 00 
		$a_80_13 = {24 63 6c 72 63 6d 64 } //$clrcmd  00 00 
	condition:
		any of ($a_*)
 
}