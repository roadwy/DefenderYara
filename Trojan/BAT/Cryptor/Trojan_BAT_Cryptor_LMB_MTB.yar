
rule Trojan_BAT_Cryptor_LMB_MTB{
	meta:
		description = "Trojan:BAT/Cryptor.LMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 05 00 00 "
		
	strings :
		$a_81_0 = {52 65 6c 65 61 73 65 5c 63 72 79 70 74 6f 72 2e 70 64 62 } //20 Release\cryptor.pdb
		$a_81_1 = {45 78 65 63 75 74 65 53 68 65 6c 6c 63 6f 64 65 } //10 ExecuteShellcode
		$a_81_2 = {5b 2b 5d 20 44 65 63 72 79 70 74 69 6e 67 20 25 75 20 62 79 74 65 73 } //5 [+] Decrypting %u bytes
		$a_81_3 = {5b 2b 5d 20 45 78 65 63 75 74 69 6e 67 20 44 6f 6e 75 74 20 53 68 65 6c 6c 63 6f 64 65 2e 2e 2e } //3 [+] Executing Donut Shellcode...
		$a_81_4 = {5b 2b 5d 20 53 75 63 63 65 73 73 66 75 6c 6c 79 20 64 65 63 72 79 70 74 65 64 20 25 75 20 62 79 74 65 73 } //2 [+] Successfully decrypted %u bytes
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*10+(#a_81_2  & 1)*5+(#a_81_3  & 1)*3+(#a_81_4  & 1)*2) >=40
 
}
rule Trojan_BAT_Cryptor_LMB_MTB_2{
	meta:
		description = "Trojan:BAT/Cryptor.LMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 04 00 00 "
		
	strings :
		$a_01_0 = {33 d2 48 8b c5 48 f7 f1 42 0f b6 44 22 07 30 04 2f 48 ff c5 49 3b ef } //20
		$a_81_1 = {47 65 74 52 65 63 6f 76 65 72 79 4b 65 79 5f 42 49 54 4c 4f 43 4b 45 52 40 40 59 41 5f 4e 50 45 41 58 41 45 41 56 } //5 GetRecoveryKey_BITLOCKER@@YA_NPEAXAEAV
		$a_81_2 = {43 72 65 61 74 65 46 69 6c 65 5f 42 49 54 4c 4f 43 4b 45 52 40 40 59 41 50 45 41 58 50 45 41 55 65 6e 63 72 79 70 74 5f 73 6f 75 72 63 65 5f 6f 70 74 40 40 50 45 41 55 5f 4d 59 42 44 5f 4b 45 59 49 4e 46 4f 40 40 50 45 41 55 5f 4d 59 42 44 5f 50 41 52 41 4d 40 40 40 5a } //3 CreateFile_BITLOCKER@@YAPEAXPEAUencrypt_source_opt@@PEAU_MYBD_KEYINFO@@PEAU_MYBD_PARAM@@@Z
		$a_81_3 = {52 65 61 64 46 69 6c 65 5f 42 49 54 4c 4f 43 4b 45 52 40 40 59 41 5f 4e 50 45 41 58 30 49 50 45 41 49 5f 4b 40 5a } //2 ReadFile_BITLOCKER@@YA_NPEAX0IPEAI_K@Z
	condition:
		((#a_01_0  & 1)*20+(#a_81_1  & 1)*5+(#a_81_2  & 1)*3+(#a_81_3  & 1)*2) >=30
 
}