
rule Trojan_BAT_FormBook_EWS_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EWS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {02 03 61 28 90 01 03 0a 0a 2b 00 90 00 } //1
		$a_81_1 = {4b 34 44 4f 4d 34 44 4e 47 48 53 4f 45 30 39 } //1 K4DOM4DNGHSOE09
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_3 = {41 65 74 50 61 6c 65 73 74 69 6e 69 61 6e } //1 AetPalestinian
		$a_01_4 = {52 67 72 63 68 61 72 74 } //1 Rgrchart
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}