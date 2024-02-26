
rule Trojan_Win64_Amadey_B_MTB{
	meta:
		description = "Trojan:Win64/Amadey.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {70 61 73 73 77 6f 72 64 20 74 79 70 65 3d 22 51 53 74 72 69 6e 67 } //02 00  password type="QString
		$a_01_1 = {50 61 73 73 20 65 6e 63 6f 64 69 6e 67 3d 22 62 61 73 65 36 34 } //02 00  Pass encoding="base64
		$a_01_2 = {6e 65 74 73 68 20 77 6c 61 6e 20 65 78 70 6f 72 74 20 70 72 6f 66 69 6c 65 20 6e 61 6d 65 } //02 00  netsh wlan export profile name
		$a_01_3 = {6e 65 74 73 68 20 77 6c 61 6e 20 73 68 6f 77 20 70 72 6f 66 69 6c 65 73 } //00 00  netsh wlan show profiles
	condition:
		any of ($a_*)
 
}