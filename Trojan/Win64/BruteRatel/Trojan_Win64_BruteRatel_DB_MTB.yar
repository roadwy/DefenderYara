
rule Trojan_Win64_BruteRatel_DB_MTB{
	meta:
		description = "Trojan:Win64/BruteRatel.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_81_0 = {5d 20 53 63 72 65 65 6e 73 68 6f 74 20 64 6f 77 6e 6c 6f 61 64 65 64 3a } //1 ] Screenshot downloaded:
		$a_81_1 = {5d 20 53 70 6f 6f 66 65 64 20 61 72 67 75 6d 65 6e 74 3a } //1 ] Spoofed argument:
		$a_81_2 = {5d 20 54 43 50 20 6c 69 73 74 65 6e 65 72 20 73 74 61 72 74 65 64 } //1 ] TCP listener started
		$a_81_3 = {5d 20 57 61 6c 6c 70 61 70 65 72 20 63 68 61 6e 67 65 64 } //1 ] Wallpaper changed
		$a_81_4 = {5d 20 43 68 69 6c 64 20 70 72 6f 63 65 73 73 20 6e 6f 74 20 73 65 74 } //1 ] Child process not set
		$a_81_5 = {5d 20 50 72 6f 63 65 73 73 20 4b 69 6c 6c 65 64 } //1 ] Process Killed
		$a_81_6 = {5d 20 44 69 72 65 63 74 6f 72 79 20 43 72 65 61 74 65 64 } //1 ] Directory Created
		$a_81_7 = {5d 20 57 6f 72 6b 73 74 61 74 69 6f 6e 20 6c 6f 63 6b 65 64 } //1 ] Workstation locked
		$a_81_8 = {5d 20 4f 62 6a 65 63 74 20 70 69 70 65 20 6e 61 6d 65 3a } //1 ] Object pipe name:
		$a_81_9 = {5d 20 44 6f 77 6e 6c 6f 61 64 20 63 6f 6d 70 6c 65 74 65 } //1 ] Download complete
		$a_81_10 = {5d 20 44 75 70 6c 69 63 61 74 65 20 6c 69 73 74 65 6e 65 72 3a } //1 ] Duplicate listener:
		$a_81_11 = {5d 20 49 6e 6a 65 63 74 65 64 20 74 6f 3a } //1 ] Injected to:
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=12
 
}