
rule Ransom_MSIL_Cryptolocker_EQ_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.EQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 10 00 00 "
		
	strings :
		$a_81_0 = {48 41 43 4b 45 52 52 41 4e 53 4f 4d 57 41 52 45 } //50 HACKERRANSOMWARE
		$a_81_1 = {59 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 76 69 64 65 6f 73 2c 20 6d 75 73 69 63 2c 20 69 6d 61 67 65 73 2c 20 64 6f 63 75 6d 65 6e 74 73 20 2e 2e 2e 20 65 74 63 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 65 6e 63 72 79 70 74 69 6f 6e } //50 Your important files videos, music, images, documents ... etc are encrypted with encryption
		$a_81_2 = {52 61 6e 73 6f 6d 44 65 63 72 79 30 72 } //50 RansomDecry0r
		$a_81_3 = {59 4a 53 4e 50 49 4c 30 63 6b 65 72 } //50 YJSNPIL0cker
		$a_81_4 = {45 6e 63 72 79 70 74 46 69 6c 65 } //20 EncryptFile
		$a_81_5 = {4d 65 73 73 61 67 65 2e 74 78 74 } //20 Message.txt
		$a_81_6 = {62 69 74 63 6f 69 6e 20 48 65 6c 70 } //20 bitcoin Help
		$a_81_7 = {54 6f 72 5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //20 Tor\explorer.exe
		$a_81_8 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //3 vssadmin delete shadows /all /quiet
		$a_81_9 = {53 65 6e 64 20 62 69 74 63 6f 69 6e 73 20 74 6f 20 74 68 69 73 20 61 64 64 72 65 73 73 } //3 Send bitcoins to this address
		$a_81_10 = {52 61 6e 73 6f 6d 48 4f 53 } //3 RansomHOS
		$a_81_11 = {61 61 61 61 62 62 62 62 61 61 61 61 62 62 62 62 61 61 61 61 62 62 62 62 61 61 61 61 62 62 62 62 } //3 aaaabbbbaaaabbbbaaaabbbbaaaabbbb
		$a_81_12 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } //1 bcdedit /set {default} recoveryenabled no
		$a_81_13 = {72 61 6e 73 6f 34 2e 6a 70 67 } //1 ranso4.jpg
		$a_81_14 = {48 65 72 6f 65 73 20 6f 66 20 74 68 65 20 53 74 6f 72 6d } //1 Heroes of the Storm
		$a_81_15 = {2e 6f 6e 69 6f 6e } //1 .onion
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*50+(#a_81_2  & 1)*50+(#a_81_3  & 1)*50+(#a_81_4  & 1)*20+(#a_81_5  & 1)*20+(#a_81_6  & 1)*20+(#a_81_7  & 1)*20+(#a_81_8  & 1)*3+(#a_81_9  & 1)*3+(#a_81_10  & 1)*3+(#a_81_11  & 1)*3+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1) >=74
 
}