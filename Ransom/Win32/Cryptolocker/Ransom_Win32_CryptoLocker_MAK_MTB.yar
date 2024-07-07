
rule Ransom_Win32_CryptoLocker_MAK_MTB{
	meta:
		description = "Ransom:Win32/CryptoLocker.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 0f 00 00 "
		
	strings :
		$a_80_0 = {2f 6c 61 6e 64 69 6e 67 } ///landing  1
		$a_80_1 = {2f 77 69 70 65 } ///wipe  1
		$a_80_2 = {2f 65 78 74 } ///ext  1
		$a_80_3 = {2f 69 67 6e 6f 72 65 } ///ignore  1
		$a_80_4 = {2f 70 72 69 6f 72 69 74 79 } ///priority  1
		$a_80_5 = {2f 73 65 72 76 69 63 65 73 } ///services  1
		$a_80_6 = {2f 6b 65 79 } ///key  1
		$a_80_7 = {47 45 4e 42 4f 54 49 44 } //GENBOTID  10
		$a_80_8 = {4b 49 4c 4c 50 52 20 62 65 67 69 6e } //KILLPR begin  1
		$a_80_9 = {4b 49 4c 4c 50 52 20 65 6e 64 } //KILLPR end  1
		$a_80_10 = {53 4d 42 46 41 53 54 20 62 65 67 69 6e } //SMBFAST begin  1
		$a_80_11 = {53 4d 42 46 41 53 54 20 65 6e 64 } //SMBFAST end  1
		$a_80_12 = {44 65 6c 65 74 69 6e 67 46 69 6c 65 73 } //DeletingFiles  1
		$a_80_13 = {52 45 41 44 4d 45 5f 46 4f 52 5f 44 45 43 52 59 50 54 2e 74 78 74 } //README_FOR_DECRYPT.txt  10
		$a_80_14 = {25 63 69 64 5f 62 6f 74 25 } //%cid_bot%  10
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*10+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*10+(#a_80_14  & 1)*10) >=40
 
}