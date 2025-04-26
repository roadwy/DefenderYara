
rule Ransom_Win32_Embargo_B{
	meta:
		description = "Ransom:Win32/Embargo.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 "
		
	strings :
		$a_01_0 = {22 6e 6f 74 65 5f 63 6f 6e 74 65 6e 74 73 22 3a 22 59 6f 75 72 20 6e 65 74 77 6f 72 6b } //2 "note_contents":"Your network
		$a_01_1 = {22 6e 6f 74 65 5f 6e 61 6d 65 22 3a 22 48 4f 57 5f 54 4f 5f 52 45 43 4f 56 45 52 5f 46 49 4c 45 53 2e 74 78 74 22 } //2 "note_name":"HOW_TO_RECOVER_FILES.txt"
		$a_01_2 = {22 66 75 6c 6c 5f 65 6e 63 72 79 70 74 5f 65 78 74 65 6e 73 69 6f 6e 73 22 3a 5b 22 } //2 "full_encrypt_extensions":["
		$a_01_3 = {22 63 72 65 64 73 22 3a 5b 22 70 6f 6c 69 63 65 2e } //1 "creds":["police.
		$a_01_4 = {22 65 78 63 6c 75 64 65 5f 70 61 74 68 73 22 3a 5b 22 } //1 "exclude_paths":["
		$a_01_5 = {22 65 78 63 6c 75 64 65 64 5f 76 6d 73 22 3a 5b 22 } //1 "excluded_vms":["
		$a_01_6 = {22 6b 69 6c 6c 5f 70 72 6f 63 73 22 3a 5b 22 } //1 "kill_procs":["
		$a_01_7 = {22 6b 69 6c 6c 5f 73 65 72 76 69 63 65 73 22 3a 5b 22 } //1 "kill_services":["
		$a_01_8 = {22 76 6d 5f 65 78 74 65 6e 73 69 6f 6e 73 22 3a 5b 22 2a 2e } //1 "vm_extensions":["*.
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=6
 
}