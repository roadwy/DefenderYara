
rule Trojan_BAT_VayneRat_CXJP_MTB{
	meta:
		description = "Trojan:BAT/VayneRat.CXJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {56 61 79 6e 65 20 52 61 74 20 2d 20 43 6c 69 65 6e 74 } //1 Vayne Rat - Client
		$a_01_1 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //1 SELECT * FROM AntivirusProduct
		$a_01_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 } //1 Windows Defender
		$a_01_3 = {6c 00 6f 00 67 00 69 00 6e 00 73 00 } //1 logins
		$a_01_4 = {75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 5f 00 76 00 61 00 6c 00 75 00 65 00 } //1 username_value
		$a_01_5 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 5f 00 76 00 61 00 6c 00 75 00 65 00 } //1 password_value
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}