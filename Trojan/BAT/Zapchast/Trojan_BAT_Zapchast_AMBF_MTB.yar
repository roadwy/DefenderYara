
rule Trojan_BAT_Zapchast_AMBF_MTB{
	meta:
		description = "Trojan:BAT/Zapchast.AMBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_00_0 = {4b 00 6f 00 41 00 4f 00 6b 00 58 00 2e 00 4d 00 58 00 75 00 75 00 4a 00 62 00 } //2 KoAOkX.MXuuJb
		$a_00_1 = {57 00 77 00 51 00 54 00 5a 00 63 00 } //2 WwQTZc
		$a_00_2 = {6b 00 72 00 6f 00 77 00 65 00 6d 00 61 00 72 00 46 00 5c 00 54 00 45 00 4e 00 2e 00 74 00 66 00 6f 00 73 00 6f 00 72 00 63 00 69 00 4d 00 5c 00 73 00 77 00 6f 00 64 00 6e 00 69 00 57 00 5c 00 3a 00 43 00 } //1 krowemarF\TEN.tfosorciM\swodniW\:C
		$a_01_3 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_01_6 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=9
 
}