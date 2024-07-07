
rule Ransom_MacOS_Kuiper_A_MTB{
	meta:
		description = "Ransom:MacOS/Kuiper.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 72 6f 6f 74 2f 6b 75 69 70 65 72 } //1 /root/kuiper
		$a_01_1 = {6d 61 69 6e 2e 52 75 6e 53 61 66 65 4d 6f 64 65 41 6e 64 47 65 74 41 64 6d 69 6e 50 72 69 76 69 6c 65 67 65 73 } //1 main.RunSafeModeAndGetAdminPrivileges
		$a_01_2 = {6d 61 69 6e 2e 43 6c 65 61 6e 4d 65 6d 6f 72 79 4b 65 79 } //1 main.CleanMemoryKey
		$a_01_3 = {52 45 41 44 4d 45 5f 54 4f 5f 44 45 43 52 59 50 54 2e 74 78 74 } //1 README_TO_DECRYPT.txt
		$a_01_4 = {6d 61 69 6e 2e 53 74 61 72 74 41 6c 6c 42 79 70 61 73 73 } //1 main.StartAllBypass
		$a_01_5 = {6d 61 69 6e 2e 52 65 6e 61 6d 65 41 6c 6c 46 69 6c 65 73 } //1 main.RenameAllFiles
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}