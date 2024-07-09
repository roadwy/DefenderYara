
rule Trojan_Win32_Proscks_A_dll{
	meta:
		description = "Trojan:Win32/Proscks.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 50 48 41 43 54 49 4f 4e 2e 64 6c 6c } //1 IPHACTION.dll
		$a_01_1 = {64 6f 4d 79 41 63 74 69 6f 6e } //1 doMyAction
		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 64 6f 66 75 6c 66 69 6c 6c } //1 http://www.dofulfill
		$a_03_3 = {73 76 63 68 6f 73 74 2e 65 78 65 20 6c 6f 61 64 69 70 68 6f 73 74 [0-04] 25 73 5c 66 69 70 6c 6f 63 6b 2e 64 6c 6c } //1
		$a_03_4 = {3c 2f 77 65 62 75 72 6c 3e [0-04] 57 65 62 53 74 61 72 74 41 63 74 69 6f 6e [0-02] 3c 67 65 74 55 73 65 64 4c 6f 61 6e 44 61 74 61 3e [0-04] 3c 2f 67 65 74 55 73 65 64 4c 6f 61 6e 44 61 74 61 3e [0-04] 3c 63 6d 64 5f 77 65 62 43 6f 3e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}