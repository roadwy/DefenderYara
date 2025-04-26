
rule Ransom_Win32_MedusaLocker_PD_MTB{
	meta:
		description = "Ransom:Win32/MedusaLocker.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 00 4f 00 48 00 4f 00 4c 00 31 00 34 00 38 00 38 00 } //1 HOHOL1488
		$a_01_1 = {50 55 54 49 4e 48 55 49 4c 4f 31 33 33 37 } //1 PUTINHUILO1337
		$a_01_2 = {45 6e 63 72 79 70 74 65 64 45 78 74 65 6e 73 69 6f 6e } //1 EncryptedExtension
		$a_01_3 = {53 00 74 00 61 00 72 00 74 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 2e 00 2e 00 } //1 Start encryption..
		$a_01_4 = {45 6e 63 72 79 70 74 65 64 45 78 74 65 6e 73 69 6f 6e 22 3a 20 22 2e 4c 41 54 43 48 4e 45 54 57 4f 52 4b 33 } //1 EncryptedExtension": ".LATCHNETWORK3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}