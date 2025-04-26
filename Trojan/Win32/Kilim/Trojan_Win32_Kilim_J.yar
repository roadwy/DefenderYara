
rule Trojan_Win32_Kilim_J{
	meta:
		description = "Trojan:Win32/Kilim.J,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 63 72 69 70 74 61 62 6c 65 5f 68 6f 73 74 22 3a 20 5b 20 22 68 74 74 70 3a 2f 2f 2a 2f 2a 22 20 5d } //1 scriptable_host": [ "http://*/*" ]
		$a_02_1 = {61 70 69 22 3a 20 5b [0-40] 22 63 6c 69 70 62 6f 61 72 64 57 72 69 74 65 } //1
		$a_00_2 = {2f 2f 47 6f 6f 67 6c 65 2f 2f 43 68 72 6f 6d 65 2f 2f 55 73 65 72 20 44 61 74 61 2f 2f 44 65 66 61 75 6c 74 2f 2f 50 72 65 66 65 72 65 6e 63 65 73 } //1 //Google//Chrome//User Data//Default//Preferences
		$a_02_3 = {63 68 72 6f 6d 65 2e 65 78 65 00 [0-08] 6f 70 65 72 61 2e 65 78 65 } //1
		$a_00_4 = {5c 77 69 6e 72 65 67 69 73 74 2e 65 72 } //1 \winregist.er
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}