
rule Trojan_Linux_FlexibleFerret_A_dha{
	meta:
		description = "Trojan:Linux/FlexibleFerret.A!dha,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 61 73 73 77 6f 72 64 20 63 61 6e 6e 6f 74 20 62 65 20 65 6d 70 74 79 2e 20 50 6c 65 61 73 65 20 65 6e 74 65 72 20 61 20 70 61 73 73 77 6f 72 64 2e } //1 Password cannot be empty. Please enter a password.
		$a_01_1 = {50 75 62 6c 69 63 20 49 50 20 41 64 64 72 65 73 73 3a } //1 Public IP Address:
		$a_01_2 = {55 70 6c 6f 61 64 20 66 61 69 6c 65 64 20 77 69 74 68 20 65 72 72 6f 72 3a } //1 Upload failed with error:
		$a_01_3 = {46 61 69 6c 65 64 20 74 6f 20 75 70 6c 6f 61 64 20 66 69 6c 65 2e 20 52 65 73 70 6f 6e 73 65 3a } //1 Failed to upload file. Response:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}