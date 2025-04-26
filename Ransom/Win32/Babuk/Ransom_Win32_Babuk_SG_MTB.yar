
rule Ransom_Win32_Babuk_SG_MTB{
	meta:
		description = "Ransom:Win32/Babuk.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {77 65 20 61 72 65 20 74 68 65 20 42 41 42 55 4b 20 74 65 61 6d } //we are the BABUK team  1
		$a_80_1 = {68 74 74 70 3a 2f 2f 62 61 62 75 6b 71 34 65 32 70 34 77 75 34 69 71 2e 6f 6e 69 6f 6e } //http://babukq4e2p4wu4iq.onion  1
		$a_80_2 = {2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } ///c vssadmin.exe delete shadows /all /quiet  1
		$a_80_3 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //CryptEncrypt  1
		$a_80_4 = {48 6f 77 20 54 6f 20 52 65 73 74 6f 72 65 20 59 6f 75 72 20 46 69 6c 65 73 } //How To Restore Your Files  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}