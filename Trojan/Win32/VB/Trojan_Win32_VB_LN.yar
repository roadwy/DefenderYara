
rule Trojan_Win32_VB_LN{
	meta:
		description = "Trojan:Win32/VB.LN,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 65 74 68 65 64 6f 75 67 61 } //1 seethedouga
		$a_01_1 = {63 00 61 00 74 00 63 00 68 00 20 00 74 00 68 00 65 00 20 00 73 00 61 00 6e 00 64 00 6d 00 61 00 6e 00 } //1 catch the sandman
		$a_01_2 = {5c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 44 00 61 00 74 00 61 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 41 00 64 00 64 00 72 00 65 00 73 00 73 00 20 00 42 00 6f 00 6f 00 6b 00 5c 00 } //1 \Application Data\Microsoft\Address Book\
		$a_01_3 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 66 00 69 00 6c 00 65 00 73 00 5c 00 69 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 49 00 45 00 58 00 50 00 4c 00 4f 00 52 00 45 00 2e 00 65 00 78 00 65 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //1 C:\Program files\internet explorer\IEXPLORE.exe http://
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}