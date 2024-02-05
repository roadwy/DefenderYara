
rule Ransom_MSIL_Filecoder_SH_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {66 69 6c 65 45 6e 63 72 79 70 74 65 64 } //fileEncrypted  01 00 
		$a_80_1 = {44 65 63 72 79 70 74 69 6f 6e 46 69 6c 65 } //DecryptionFile  01 00 
		$a_80_2 = {72 61 6e 73 6f 6d 77 61 72 65 40 67 6d 61 69 6c 2e 63 6f 6d } //ransomware@gmail.com  01 00 
		$a_80_3 = {4b 41 20 52 41 4e 53 4f 4d 57 41 52 45 } //KA RANSOMWARE  01 00 
		$a_00_4 = {11 73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 00 0f 2f 00 72 00 20 00 2f 00 74 00 20 00 30 } //00 00 
	condition:
		any of ($a_*)
 
}