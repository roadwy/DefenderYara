
rule Ransom_Win32_Zudochka_A_MSR{
	meta:
		description = "Ransom:Win32/Zudochka.A!MSR,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //01 00  All your files have been encrypted!
		$a_01_1 = {44 45 43 52 59 50 54 5f 46 49 4c 45 53 2e 54 58 54 } //01 00  DECRYPT_FILES.TXT
		$a_01_2 = {5c 48 4f 57 20 54 4f 20 52 45 53 54 4f 52 45 20 45 4e 43 52 59 50 54 45 44 20 46 49 4c 45 53 2e 54 58 54 } //01 00  \HOW TO RESTORE ENCRYPTED FILES.TXT
		$a_01_3 = {64 65 63 72 79 70 74 6f 72 20 61 6e 64 20 61 20 75 6e 69 71 75 65 20 64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 } //00 00  decryptor and a unique decryption key
	condition:
		any of ($a_*)
 
}