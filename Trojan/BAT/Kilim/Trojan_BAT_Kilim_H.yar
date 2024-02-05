
rule Trojan_BAT_Kilim_H{
	meta:
		description = "Trojan:BAT/Kilim.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 00 41 00 42 00 6b 00 41 00 47 00 38 00 41 00 59 00 77 00 41 00 75 00 41 00 47 00 4d 00 41 00 63 00 67 00 42 00 34 00 41 00 41 00 3d 00 3d 00 } //01 00 
		$a_01_1 = {52 00 41 00 42 00 70 00 41 00 48 00 4d 00 41 00 59 00 51 00 42 00 69 00 41 00 47 00 77 00 41 00 5a 00 51 00 42 00 42 00 41 00 48 00 55 00 41 00 64 00 41 00 42 00 76 00 41 00 46 00 55 00 41 00 63 00 41 00 42 00 6b 00 41 00 47 00 45 00 41 00 64 00 41 00 42 00 6c 00 41 00 45 00 4d 00 41 00 61 00 41 00 42 00 6c 00 41 00 47 00 4d 00 41 00 61 00 77 00 42 00 7a 00 41 00 45 00 4d 00 41 00 61 00 41 00 42 00 6c 00 41 00 47 00 4d 00 41 00 61 00 77 00 42 00 69 00 41 00 47 00 38 00 41 00 65 00 41 00 42 00 57 00 41 00 47 00 45 00 41 00 62 00 41 00 42 00 31 00 41 00 47 00 55 00 41 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}