
rule Trojan_BAT_Formbook_RDH_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {34 30 62 32 36 61 61 34 2d 39 37 33 31 2d 34 38 64 31 2d 61 31 39 38 2d 65 63 62 37 35 31 62 62 34 63 34 65 } //1 40b26aa4-9731-48d1-a198-ecb751bb4c4e
		$a_01_1 = {37 21 30 79 45 4b 2d 29 73 40 30 47 31 5e 4d 5c 2a 5c 5c 51 5a 45 2f 5a 77 50 30 } //1 7!0yEK-)s@0G1^M\*\\QZE/ZwP0
		$a_01_2 = {4e 35 35 36 37 33 36 } //1 N556736
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}