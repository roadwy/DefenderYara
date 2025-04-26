
rule Ransom_Win32_HydraCrypt_PAA_MTB{
	meta:
		description = "Ransom:Win32/HydraCrypt.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 00 6c 00 6c 00 20 00 59 00 6f 00 75 00 72 00 20 00 46 00 69 00 6c 00 65 00 73 00 20 00 48 00 61 00 73 00 20 00 42 00 65 00 65 00 6e 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1 All Your Files Has Been Encrypted
		$a_01_1 = {77 62 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 71 75 69 65 74 } //1 wbadmin delete catalog -quiet
		$a_01_2 = {5c 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 2d 00 6d 00 65 00 2e 00 74 00 78 00 74 00 } //1 \Decrypt-me.txt
		$a_01_3 = {66 75 63 6b 79 6f 75 66 75 63 6b 79 6f 75 } //1 fuckyoufuckyou
		$a_01_4 = {70 6b 65 79 2e 74 78 74 } //1 pkey.txt
		$a_01_5 = {49 44 6b 2e 74 78 74 } //1 IDk.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}