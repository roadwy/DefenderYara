
rule Trojan_Win32_Kilim_AC_bit{
	meta:
		description = "Trojan:Win32/Kilim.AC!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {56 4d 77 61 72 65 00 56 69 72 74 75 61 6c 42 6f 78 } //1
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
		$a_03_2 = {63 68 72 6f 6d 65 2e 65 78 65 00 [0-08] 6f 70 65 72 61 2e 65 78 65 } //1
		$a_01_3 = {2f 2f 47 6f 6f 67 6c 65 2f 2f 43 68 72 6f 6d 65 2f 2f 55 73 65 72 20 44 61 74 61 2f 2f 44 65 66 61 75 6c 74 2f 2f 50 72 65 66 65 72 65 6e 63 65 73 } //1 //Google//Chrome//User Data//Default//Preferences
		$a_03_4 = {66 65 69 64 6f 77 6e 73 2e 63 6f 6d 2f [0-20] 2e 70 68 70 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}