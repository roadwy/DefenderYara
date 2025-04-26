
rule Ransom_MacOS_Ransomwhere_A_MTB{
	meta:
		description = "Ransom:MacOS/Ransomwhere.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {67 69 74 68 75 62 2e 63 6f 6d 2f 68 61 7a 63 6f 64 2f 72 61 6e 73 6f 6d 77 68 65 72 65 } //1 github.com/hazcod/ransomwhere
		$a_01_1 = {63 72 79 70 74 6f 2e 45 6e 63 72 79 70 74 46 69 6c 65 } //1 crypto.EncryptFile
		$a_01_2 = {66 69 6c 65 2e 57 61 6c 6b 46 69 6c 65 73 } //1 file.WalkFiles
		$a_01_3 = {73 6e 61 70 73 68 6f 74 73 2e 57 69 70 65 53 6e 61 70 73 68 6f 74 73 } //1 snapshots.WipeSnapshots
		$a_01_4 = {63 72 79 70 74 6f 2e 44 65 63 72 79 70 74 46 69 6c 65 } //1 crypto.DecryptFile
		$a_01_5 = {41 47 45 2d 53 45 43 52 45 54 2d 4b 45 59 2d } //1 AGE-SECRET-KEY-
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}