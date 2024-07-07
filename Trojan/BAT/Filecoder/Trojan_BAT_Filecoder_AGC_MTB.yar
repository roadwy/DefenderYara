
rule Trojan_BAT_Filecoder_AGC_MTB{
	meta:
		description = "Trojan:BAT/Filecoder.AGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {65 69 6b 6c 6f 74 40 68 69 32 2e 69 6e } //eiklot@hi2.in  1
		$a_80_1 = {48 6f 77 5f 52 65 63 6f 76 65 72 5f 46 69 6c 65 73 2e 74 78 74 } //How_Recover_Files.txt  1
		$a_80_2 = {4a 65 73 75 73 43 72 79 70 74 } //JesusCrypt  1
		$a_80_3 = {45 6e 63 72 79 70 74 46 69 6c 65 } //EncryptFile  1
		$a_80_4 = {53 65 6e 64 53 65 72 76 65 72 49 6e 66 6f 40 68 69 74 6c 65 72 2e 72 6f 63 6b 73 } //SendServerInfo@hitler.rocks  1
		$a_80_5 = {6d 61 69 6c 2e 63 6f 63 6b 2e 6c 69 } //mail.cock.li  1
		$a_80_6 = {4a 65 73 75 73 5f 52 61 6e 73 6f 6d } //Jesus_Ransom  1
		$a_80_7 = {41 6c 6c 20 59 6f 75 72 20 46 69 6c 65 73 20 45 6e 63 72 79 70 74 65 64 20 42 79 20 4a 65 73 75 73 20 52 61 6e 73 6f 6d 77 61 72 65 } //All Your Files Encrypted By Jesus Ransomware  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}