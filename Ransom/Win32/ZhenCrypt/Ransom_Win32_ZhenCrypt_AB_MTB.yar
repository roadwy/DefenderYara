
rule Ransom_Win32_ZhenCrypt_AB_MTB{
	meta:
		description = "Ransom:Win32/ZhenCrypt.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 65 61 64 20 46 6f 72 20 44 65 63 72 79 70 74 69 6f 6e 2e 6c 6e 6b } //01 00  Read For Decryption.lnk
		$a_81_1 = {44 65 63 72 79 70 74 6f 72 2e 6c 6e 6b } //01 00  Decryptor.lnk
		$a_81_2 = {2f 67 72 61 6e 74 20 55 73 65 72 73 3a 46 } //01 00  /grant Users:F
		$a_81_3 = {50 61 79 6d 65 6e 74 20 43 68 65 63 6b 65 64 21 } //01 00  Payment Checked!
		$a_81_4 = {68 6f 77 2b 74 6f 2b 62 75 79 2b 62 69 74 63 6f 69 6e } //01 00  how+to+buy+bitcoin
		$a_81_5 = {5c 44 65 73 6b 74 6f 70 5c 44 65 63 72 79 70 74 69 6f 6e 20 4e 6f 74 65 2e 74 78 74 } //01 00  \Desktop\Decryption Note.txt
		$a_81_6 = {53 65 6e 64 20 30 2e 33 20 42 54 43 20 54 6f 3a } //01 00  Send 0.3 BTC To:
		$a_81_7 = {5a 68 65 6e 21 } //00 00  Zhen!
		$a_00_8 = {5d 04 00 00 } //8b 4e 
	condition:
		any of ($a_*)
 
}