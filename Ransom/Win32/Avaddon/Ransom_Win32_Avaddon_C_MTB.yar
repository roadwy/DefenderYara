
rule Ransom_Win32_Avaddon_C_MTB{
	meta:
		description = "Ransom:Win32/Avaddon.C!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 6e 65 74 77 6f 72 6b 20 68 61 73 20 62 65 65 6e 20 69 6e 66 65 63 74 65 64 } //01 00  Your network has been infected
		$a_01_1 = {2e 6f 6e 69 6f 6e } //01 00  .onion
		$a_01_2 = {54 6f 72 20 62 72 6f 77 73 65 72 } //01 00  Tor browser
		$a_01_3 = {44 6f 20 6e 6f 74 20 74 72 79 20 74 6f 20 72 65 63 6f 76 65 72 } //01 00  Do not try to recover
		$a_01_4 = {66 69 6c 65 73 20 66 6f 72 65 76 65 72 } //02 00  files forever
		$a_01_5 = {3c 74 69 74 6c 65 3e 41 76 61 64 64 6f 6e 3c 2f 74 69 74 6c 65 3e } //00 00  <title>Avaddon</title>
		$a_01_6 = {00 5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}