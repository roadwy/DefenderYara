
rule Ransom_MSIL_Cryptolocker_DY_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //01 00  Your files are encrypted
		$a_81_1 = {52 45 41 44 5f 4d 45 2e 63 72 79 70 74 65 64 2e 74 78 74 } //01 00  READ_ME.crypted.txt
		$a_81_2 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //01 00  @protonmail.com
		$a_81_3 = {4e 6f 20 66 69 6c 65 73 20 74 6f 20 65 6e 63 72 79 70 74 } //00 00  No files to encrypt
	condition:
		any of ($a_*)
 
}