
rule Trojan_BAT_Redline_AMAJ_MTB{
	meta:
		description = "Trojan:BAT/Redline.AMAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 65 76 70 37 4c 4a 4c 6f 78 50 42 78 58 4d 6f 4e 50 65 76 } //2 Pevp7LJLoxPBxXMoNPev
		$a_01_1 = {6f 59 62 46 55 77 4a 4c 67 6c 39 56 56 4b 4d 45 55 72 6c 63 } //1 oYbFUwJLgl9VVKMEUrlc
		$a_01_2 = {74 56 4b 67 67 30 4a 4c 30 69 73 77 57 6d 31 71 72 49 47 34 } //1 tVKgg0JL0iswWm1qrIG4
		$a_01_3 = {55 53 4e 5a 4e 42 43 4c 45 4f 41 53 53 53 42 48 52 50 56 48 42 59 41 42 4f 4d 4f 58 50 } //1 USNZNBCLEOASSSBHRPVHBYABOMOXP
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}