
rule Trojan_BAT_Bepush_H{
	meta:
		description = "Trojan:BAT/Bepush.H,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 00 61 00 79 00 64 00 69 00 6c 00 65 00 } //01 00  vaydile
		$a_03_1 = {76 00 6d 00 77 00 61 00 72 00 65 00 90 02 05 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 42 00 6f 00 78 00 90 00 } //01 00 
		$a_01_2 = {5c 00 4d 00 6f 00 7a 00 69 00 6c 00 61 00 5c 00 73 00 61 00 62 00 69 00 74 00 2e 00 61 00 75 00 33 00 } //01 00  \Mozila\sabit.au3
		$a_01_3 = {5c 00 4d 00 6f 00 7a 00 69 00 6c 00 61 00 5c 00 66 00 6f 00 72 00 63 00 65 00 2e 00 61 00 75 00 33 00 } //00 00  \Mozila\force.au3
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}