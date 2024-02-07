
rule Ransom_MSIL_DarkCrypt_PAA_MTB{
	meta:
		description = "Ransom:MSIL/DarkCrypt.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 61 6e 73 6f 6d 77 61 72 65 } //01 00  ransomware
		$a_01_1 = {57 00 69 00 6e 00 33 00 32 00 5f 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00 } //01 00  Win32_ShadowCopy
		$a_01_2 = {5c 00 44 00 61 00 72 00 6b 00 43 00 72 00 79 00 70 00 74 00 5f 00 4d 00 61 00 73 00 73 00 61 00 67 00 65 00 2e 00 74 00 78 00 74 00 } //01 00  \DarkCrypt_Massage.txt
		$a_01_3 = {49 00 6d 00 70 00 6f 00 72 00 74 00 61 00 6e 00 74 00 20 00 54 00 68 00 69 00 6e 00 67 00 73 00 20 00 41 00 72 00 65 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //00 00  Important Things Are Encrypted
	condition:
		any of ($a_*)
 
}