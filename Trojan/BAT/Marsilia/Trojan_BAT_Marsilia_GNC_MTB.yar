
rule Trojan_BAT_Marsilia_GNC_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.GNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {13 05 11 04 17 59 13 04 2b 23 08 2d 20 06 11 05 02 7b 21 00 00 04 11 06 91 09 17 59 1f 1f 5f 63 20 ff 00 00 00 09 1f 1f 5f 63 5f d2 9c 11 06 15 58 13 06 11 06 03 2f 87 } //10
		$a_80_1 = {6e 6e 6a 6e 6e 6d 6c 2e 67 69 74 68 75 62 2e 69 6f } //nnjnnml.github.io  1
		$a_80_2 = {5c 62 72 6f 77 73 65 72 50 61 73 73 77 6f 72 64 73 } //\browserPasswords  1
		$a_80_3 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //encrypted_key  1
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}