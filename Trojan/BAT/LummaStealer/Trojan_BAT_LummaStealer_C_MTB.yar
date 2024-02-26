
rule Trojan_BAT_LummaStealer_C_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {52 00 65 00 6d 00 6f 00 76 00 65 00 20 00 2d 00 49 00 74 00 65 00 6d 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 79 00 } //02 00  Remove -ItemProperty
		$a_01_1 = {27 00 48 00 4b 00 43 00 55 00 3a 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 27 00 20 00 2d 00 4e 00 61 00 6d 00 65 00 } //02 00  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name
		$a_01_2 = {67 00 6e 00 69 00 72 00 74 00 53 00 } //02 00  gnirtS
		$a_01_3 = {65 00 70 00 79 00 54 00 79 00 74 00 72 00 65 00 70 00 6f 00 72 00 50 00 2d 00 } //02 00  epyTytreporP-
		$a_01_4 = {6c 00 6c 00 65 00 68 00 73 00 } //02 00  llehs
		$a_01_5 = {65 00 75 00 6c 00 61 00 56 00 } //02 00  eulaV
		$a_01_6 = {70 00 6f 00 77 00 65 00 72 00 } //00 00  power
	condition:
		any of ($a_*)
 
}