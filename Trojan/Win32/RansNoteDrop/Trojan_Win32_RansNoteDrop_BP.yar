
rule Trojan_Win32_RansNoteDrop_BP{
	meta:
		description = "Trojan:Win32/RansNoteDrop.BP,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 6f 72 70 6c 65 61 6b 73 2e 6e 65 74 } //1 corpleaks.net
		$a_01_1 = {68 78 74 32 35 34 61 79 67 72 73 7a 69 65 6a 6e 2e 6f 6e 69 6f 6e } //1 hxt254aygrsziejn.onion
		$a_01_2 = {74 75 74 61 6e 6f 74 61 2e 63 6f 6d } //1 tutanota.com
		$a_01_3 = {70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d 20 } //1 protonmail.com 
		$a_01_4 = {63 72 79 70 74 33 32 2e 64 6c 6c } //1 crypt32.dll
		$a_01_5 = {47 65 74 44 72 69 76 65 54 79 70 65 57 } //1 GetDriveTypeW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}