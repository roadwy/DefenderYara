
rule Trojan_Win32_SuperProfLPE_A_ibt{
	meta:
		description = "Trojan:Win32/SuperProfLPE.A!ibt,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 07 00 00 "
		
	strings :
		$a_80_0 = {63 72 65 61 74 65 6d 6f 75 6e 74 70 6f 69 6e 74 00 } //createmountpoint  1
		$a_80_1 = {63 72 65 61 74 65 6e 61 74 69 76 65 73 79 6d 6c 69 6e 6b 00 } //createnativesymlink  1
		$a_80_2 = {2e 65 78 65 2e 6c 6f 63 61 6c 00 } //.exe.local  1
		$a_80_3 = {5c 63 6f 6d 63 74 6c 33 32 2e 64 6c 6c 00 } //\comctl32.dll  1
		$a_80_4 = {6e 74 63 72 65 61 74 65 73 79 6d 62 6f 6c 69 63 6c 69 6e 6b 6f 62 6a 65 63 74 00 } //ntcreatesymboliclinkobject  1
		$a_80_5 = {63 6f 6e 76 65 72 74 73 74 72 69 6e 67 73 65 63 75 72 69 74 79 64 65 73 63 72 69 70 74 6f 72 74 6f 73 65 63 75 72 69 74 79 64 65 73 63 72 69 70 74 6f 72 77 00 } //convertstringsecuritydescriptortosecuritydescriptorw  1
		$a_80_6 = {6e 74 75 73 65 72 2e 64 61 74 00 } //ntuser.dat  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=5
 
}