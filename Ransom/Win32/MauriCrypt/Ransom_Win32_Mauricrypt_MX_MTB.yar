
rule Ransom_Win32_Mauricrypt_MX_MTB{
	meta:
		description = "Ransom:Win32/Mauricrypt.MX!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {56 4f 53 20 46 49 43 48 49 45 52 53 20 4f 4e 54 20 45 54 45 20 43 48 49 46 46 52 45 53 } //1 VOS FICHIERS ONT ETE CHIFFRES
		$a_01_1 = {45 4e 56 4f 59 45 52 20 25 73 20 50 41 52 20 54 45 4c 45 50 41 54 48 49 45 } //1 ENVOYER %s PAR TELEPATHIE
		$a_01_2 = {4c 45 20 59 4f 47 41 20 50 45 55 54 20 41 49 44 45 52 20 45 4e } //1 LE YOGA PEUT AIDER EN
		$a_01_3 = {67 69 74 68 75 62 2e 63 6f 6d 2f 6d 61 75 72 69 38 37 30 2f 72 61 6e 73 6f 6d 77 61 72 65 } //1 github.com/mauri870/ransomware
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}