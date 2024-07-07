
rule Ransom_MSIL_Cryptolocker_DT_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.DT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 08 00 00 "
		
	strings :
		$a_81_0 = {4b 65 72 6e 73 6f 6d 77 61 72 65 } //50 Kernsomware
		$a_81_1 = {45 78 65 63 75 74 69 6f 6e 65 72 20 52 61 6e 73 6f 6d 77 61 72 65 } //50 Executioner Ransomware
		$a_81_2 = {2e 4b 65 72 6e } //20 .Kern
		$a_81_3 = {72 61 6e 73 6f 6d 2e 6a 70 67 } //20 ransom.jpg
		$a_81_4 = {59 6f 75 72 20 46 69 6c 65 73 20 48 61 76 65 20 42 65 65 6e 20 45 6e 63 72 79 70 74 65 64 } //3 Your Files Have Been Encrypted
		$a_81_5 = {79 6f 75 72 20 66 69 6c 65 73 20 41 72 65 20 73 61 66 65 6c 79 20 45 6e 63 72 79 70 74 65 64 } //3 your files Are safely Encrypted
		$a_81_6 = {42 69 74 63 6f 69 6e } //1 Bitcoin
		$a_81_7 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 @protonmail.com
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*50+(#a_81_2  & 1)*20+(#a_81_3  & 1)*20+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=74
 
}