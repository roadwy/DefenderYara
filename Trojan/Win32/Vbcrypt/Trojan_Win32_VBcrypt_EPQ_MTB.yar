
rule Trojan_Win32_VBcrypt_EPQ_MTB{
	meta:
		description = "Trojan:Win32/VBcrypt.EPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {73 6c 69 65 76 6f 76 69 74 73 65 72 6e 65 } //1 slievovitserne
		$a_81_1 = {56 49 4c 44 53 4b 41 42 } //1 VILDSKAB
		$a_81_2 = {48 6f 73 69 65 72 } //1 Hosier
		$a_81_3 = {74 69 64 73 67 6c 6f 73 65 } //1 tidsglose
		$a_81_4 = {46 6f 72 68 61 6e 64 6c 69 6e 67 73 67 72 75 6e 64 6c 61 67 65 6e 65 } //1 Forhandlingsgrundlagene
		$a_81_5 = {54 45 4c 45 46 4f 4e 4b 44 45 52 4e 45 } //1 TELEFONKDERNE
		$a_81_6 = {48 6f 6e 6f 72 61 72 69 65 73 33 } //1 Honoraries3
		$a_81_7 = {53 61 70 6c 69 6e 67 73 } //1 Saplings
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}