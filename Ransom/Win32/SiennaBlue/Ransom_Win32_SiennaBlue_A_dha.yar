
rule Ransom_Win32_SiennaBlue_A_dha{
	meta:
		description = "Ransom:Win32/SiennaBlue.A!dha,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 64 65 76 65 6c 6f 70 6d 65 6e 74 2f 77 6f 72 6b 69 6e 67 5f 70 72 6f 6a 65 63 74 2f 73 72 63 2f 48 6f 6c 79 47 68 6f 73 74 50 72 6f 6a 65 63 74 2f } //2 /development/working_project/src/HolyGhostProject/
		$a_01_1 = {2f 64 65 76 65 6c 6f 70 6d 65 6e 74 2f 73 72 63 2f 48 6f 6c 79 4c 6f 63 6b 65 72 2f } //2 /development/src/HolyLocker/
		$a_01_2 = {2f 64 65 76 65 6c 6f 70 6d 65 6e 74 2f 73 72 63 2f 48 6f 6c 79 47 68 6f 73 74 50 72 6f 6a 65 63 74 2f } //2 /development/src/HolyGhostProject/
		$a_01_3 = {32 33 41 53 33 32 64 66 32 31 } //1 23AS32df21
		$a_01_4 = {68 74 74 70 3a 2f 2f 31 39 33 2e 35 36 2e 32 39 2e 31 32 33 } //1 http://193.56.29.123
		$a_01_5 = {61 64 6d 2d 6b 61 72 73 61 69 72 } //1 adm-karsair
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}