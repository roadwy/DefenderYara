
rule Trojan_BAT_SoldierAudio_A_dha{
	meta:
		description = "Trojan:BAT/SoldierAudio.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 56 00 49 00 44 00 49 00 41 00 43 00 6f 00 72 00 70 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_03_1 = {41 00 75 00 64 00 69 00 6f 00 43 00 61 00 72 00 64 00 90 02 01 44 00 72 00 69 00 76 00 65 00 72 00 90 02 01 53 00 65 00 72 00 76 00 69 00 63 00 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}