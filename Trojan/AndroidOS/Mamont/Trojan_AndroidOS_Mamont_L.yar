
rule Trojan_AndroidOS_Mamont_L{
	meta:
		description = "Trojan:AndroidOS/Mamont.L,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 76 74 6f 76 79 6b 75 70 2e 61 75 74 6f 73 2f 6e 6f 70 65 73 73 6d 69 73 69 6f 6e } //2 avtovykup.autos/nopessmision
		$a_01_1 = {72 65 61 64 4c 61 73 74 31 30 4d 65 73 73 61 67 65 73 } //2 readLast10Messages
		$a_01_2 = {73 68 6f 77 50 65 72 6d 69 73 73 69 6f 6e 41 63 63 65 73 4d 65 73 73 61 67 65 } //2 showPermissionAccesMessage
		$a_01_3 = {63 68 65 63 6b 53 65 72 76 65 72 52 65 73 70 6f 6e 73 65 41 6e 64 52 65 71 75 65 73 74 50 65 72 6d 69 73 73 69 6f 6e 73 } //2 checkServerResponseAndRequestPermissions
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}