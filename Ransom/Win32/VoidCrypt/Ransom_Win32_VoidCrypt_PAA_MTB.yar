
rule Ransom_Win32_VoidCrypt_PAA_MTB{
	meta:
		description = "Ransom:Win32/VoidCrypt.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 05 00 00 "
		
	strings :
		$a_01_0 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } //10 bcdedit /set {default} recoveryenabled no
		$a_01_1 = {66 75 63 6b 79 6f 75 66 75 63 6b 79 6f 75 } //10 fuckyoufuckyou
		$a_01_2 = {44 69 73 61 62 6c 65 54 61 73 6b 6d 67 72 } //10 DisableTaskmgr
		$a_00_3 = {41 00 6c 00 6c 00 20 00 59 00 6f 00 75 00 72 00 20 00 46 00 69 00 6c 00 65 00 73 00 20 00 48 00 61 00 73 00 20 00 42 00 65 00 65 00 6e 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //5 All Your Files Has Been Encrypted
		$a_00_4 = {44 00 65 00 63 00 72 00 79 00 70 00 74 00 2d 00 69 00 6e 00 66 00 6f 00 2e 00 74 00 78 00 74 00 } //5 Decrypt-info.txt
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_00_3  & 1)*5+(#a_00_4  & 1)*5) >=35
 
}