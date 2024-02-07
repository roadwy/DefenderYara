
rule Trojan_Win32_Adialer_BAF{
	meta:
		description = "Trojan:Win32/Adialer.BAF,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 6f 73 74 3a 20 90 02 10 2e 74 6f 6e 73 69 74 65 2e 62 69 7a 90 00 } //01 00 
		$a_01_1 = {4d 50 53 6f 63 6b 4c 69 62 } //01 00  MPSockLib
		$a_01_2 = {2f 72 70 2e 70 68 70 3f 61 3d } //01 00  /rp.php?a=
		$a_01_3 = {56 61 6c 69 64 61 74 69 6f 6e 20 65 6e 20 63 6f 75 72 73 2e 2e 2e } //01 00  Validation en cours...
		$a_01_4 = {33 30 20 6d 69 6e 75 74 65 73 20 64 65 20 76 69 73 69 6f 20 73 65 78 65 20 } //00 00  30 minutes de visio sexe 
	condition:
		any of ($a_*)
 
}