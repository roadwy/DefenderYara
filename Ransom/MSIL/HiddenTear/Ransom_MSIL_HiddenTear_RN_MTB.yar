
rule Ransom_MSIL_HiddenTear_RN_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.RN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 43 6f 6d 70 75 74 65 72 20 63 6f 64 65 20 6f 6e 20 61 20 73 63 72 65 65 6e 20 77 69 74 68 20 61 20 73 6b 75 6c 6c 20 72 65 70 72 65 73 65 6e 74 69 6e 67 20 61 20 63 6f 6d 70 75 74 65 72 20 76 69 72 75 73 20 2f 20 6d 61 6c 77 61 72 65 20 61 74 74 61 63 6b 2e } //5 LComputer code on a screen with a skull representing a computer virus / malware attack.
		$a_01_1 = {45 6e 63 72 79 70 74 4f 72 44 65 63 72 79 70 74 46 69 6c 65 } //1 EncryptOrDecryptFile
		$a_01_2 = {41 63 74 69 6f 6e 45 6e 63 72 79 70 74 } //1 ActionEncrypt
		$a_01_3 = {41 63 74 69 6f 6e 44 65 63 72 79 70 74 } //1 ActionDecrypt
		$a_01_4 = {72 65 68 61 5f 72 61 6e 73 6f 6d 77 61 72 65 5f 36 35 30 78 33 38 31 } //5 reha_ransomware_650x381
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*5) >=7
 
}