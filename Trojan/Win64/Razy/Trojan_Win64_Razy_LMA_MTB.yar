
rule Trojan_Win64_Razy_LMA_MTB{
	meta:
		description = "Trojan:Win64/Razy.LMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffff99 00 ffffff99 00 11 00 00 "
		
	strings :
		$a_81_0 = {5b 44 45 42 55 47 5d 20 43 75 72 72 65 6e 74 3a } //1 [DEBUG] Current:
		$a_81_1 = {5b 44 45 42 55 47 5d 20 44 6f 77 6e 6c 6f 61 64 20 55 52 4c 3a } //2 [DEBUG] Download URL:
		$a_81_2 = {5b 44 45 42 55 47 5d 20 44 6f 77 6e 6c 6f 61 64 69 6e 67 20 74 6f 3a } //3 [DEBUG] Downloading to:
		$a_81_3 = {64 6f 77 6e 6c 6f 61 64 55 72 6c } //4 downloadUrl
		$a_81_4 = {5b 45 52 52 4f 52 5d 20 46 69 6c 65 20 74 6f 6f 20 73 6d 61 6c 6c 2c 20 70 72 6f 62 61 62 6c 79 20 6e 6f 74 20 76 61 6c 69 64 } //5 [ERROR] File too small, probably not valid
		$a_81_5 = {5b 45 52 52 4f 52 5d 20 46 61 69 6c 65 64 20 74 6f 20 63 72 65 61 74 65 20 6e 65 77 20 66 69 6c 65 } //6 [ERROR] Failed to create new file
		$a_81_6 = {5b 53 55 43 43 45 53 53 5d 20 44 6f 77 6e 6c 6f 61 64 65 64 } //7 [SUCCESS] Downloaded
		$a_81_7 = {5b 44 45 42 55 47 5d 20 44 65 6c 65 74 69 6e 67 20 6f 6c 64 20 62 61 63 6b 75 70 2e 2e 2e } //8 [DEBUG] Deleting old backup...
		$a_81_8 = {5b 44 45 42 55 47 5d 20 52 65 6e 61 6d 69 6e 67 20 63 75 72 72 65 6e 74 20 74 6f 20 2e 6f 6c 64 2e 2e 2e } //9 [DEBUG] Renaming current to .old...
		$a_81_9 = {5b 45 52 52 4f 52 5d 20 46 61 69 6c 65 64 20 74 6f 20 72 65 6e 61 6d 65 20 63 75 72 72 65 6e 74 20 66 69 6c 65 } //10 [ERROR] Failed to rename current file
		$a_81_10 = {5b 44 45 42 55 47 5d 20 4d 6f 76 69 6e 67 20 6e 65 77 20 66 69 6c 65 20 74 6f 20 63 75 72 72 65 6e 74 2e 2e 2e } //11 [DEBUG] Moving new file to current...
		$a_81_11 = {5b 45 52 52 4f 52 5d 20 46 61 69 6c 65 64 20 74 6f 20 6d 6f 76 65 20 6e 65 77 20 66 69 6c 65 } //12 [ERROR] Failed to move new file
		$a_81_12 = {5b 44 45 42 55 47 5d 20 4c 61 75 6e 63 68 69 6e 67 20 6e 65 77 20 70 72 6f 63 65 73 73 2e 2e 2e } //13 [DEBUG] Launching new process...
		$a_81_13 = {63 20 74 69 6d 65 6f 75 74 20 33 20 3e 6e 75 6c } //14 c timeout 3 >nul
		$a_81_14 = {41 55 54 48 45 4e 54 49 43 41 54 49 4f 4e 5f 53 55 43 43 45 53 53 46 55 4c } //15 AUTHENTICATION_SUCCESSFUL
		$a_81_15 = {5b 53 55 43 43 45 53 53 5d 20 4e 65 77 20 70 72 6f 63 65 73 73 20 73 74 61 72 74 65 64 } //16 [SUCCESS] New process started
		$a_81_16 = {5b 45 52 52 4f 52 5d 20 46 61 69 6c 65 64 20 74 6f 20 6c 61 75 6e 63 68 20 6e 65 77 20 70 72 6f 63 65 73 73 } //17 [ERROR] Failed to launch new process
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*3+(#a_81_3  & 1)*4+(#a_81_4  & 1)*5+(#a_81_5  & 1)*6+(#a_81_6  & 1)*7+(#a_81_7  & 1)*8+(#a_81_8  & 1)*9+(#a_81_9  & 1)*10+(#a_81_10  & 1)*11+(#a_81_11  & 1)*12+(#a_81_12  & 1)*13+(#a_81_13  & 1)*14+(#a_81_14  & 1)*15+(#a_81_15  & 1)*16+(#a_81_16  & 1)*17) >=153
 
}