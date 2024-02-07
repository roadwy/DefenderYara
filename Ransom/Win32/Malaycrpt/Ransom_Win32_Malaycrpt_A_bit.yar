
rule Ransom_Win32_Malaycrpt_A_bit{
	meta:
		description = "Ransom:Win32/Malaycrpt.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 48 4f 57 20 54 4f 20 44 45 43 52 59 50 54 20 46 49 4c 45 53 2e 74 78 74 } //01 00  \HOW TO DECRYPT FILES.txt
		$a_01_1 = {68 74 74 70 3a 2f 2f 63 72 79 70 74 34 34 33 73 67 74 6b 79 7a 34 6c 2e 6f 6e 69 6f 6e } //01 00  http://crypt443sgtkyz4l.onion
		$a_01_2 = {2e 2a 3f 5c 2e 63 72 79 70 74 } //01 00  .*?\.crypt
		$a_01_3 = {5c 6e 74 75 73 65 72 2e 70 72 6f 66 69 6c 65 } //00 00  \ntuser.profile
	condition:
		any of ($a_*)
 
}