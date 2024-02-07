
rule Trojan_BAT_Tedy_PHK_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 69 6e 74 4e 6f 74 69 66 79 50 6f 74 61 74 6f 2e 65 78 65 } //01 00  PrintNotifyPotato.exe
		$a_01_1 = {35 35 30 38 39 64 36 66 2d 36 35 64 37 2d 34 66 31 66 2d 61 31 64 35 2d 35 38 33 65 35 63 35 34 61 62 36 37 } //00 00  55089d6f-65d7-4f1f-a1d5-583e5c54ab67
	condition:
		any of ($a_*)
 
}