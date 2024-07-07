
rule Trojan_Win64_Amadey_RDL_MTB{
	meta:
		description = "Trojan:Win64/Amadey.RDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73 5c } //1 \Mozilla\Firefox\Profiles\
		$a_01_1 = {5c 54 6f 72 42 72 6f 77 73 65 72 5c 44 61 74 61 5c 42 72 6f 77 73 65 72 5c 70 72 6f 66 69 6c 65 2e 64 65 66 61 75 6c 74 } //1 \TorBrowser\Data\Browser\profile.default
		$a_01_2 = {22 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 22 3a 22 28 5b 5e 22 5d 2b 29 22 } //1 "encryptedPassword":"([^"]+)"
		$a_01_3 = {5c 6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //1 \logins.json
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}