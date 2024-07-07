
rule Trojan_Win32_Marte_CAMP_MTB{
	meta:
		description = "Trojan:Win32/Marte.CAMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4a 6b 61 66 6f 61 65 73 6a 67 66 69 61 4a 69 61 67 66 69 65 61 6a 67 } //1 JkafoaesjgfiaJiagfieajg
		$a_01_1 = {4e 6f 61 73 67 69 6f 65 61 73 6a 67 73 73 } //1 Noasgioeasjgss
		$a_01_2 = {4c 72 6f 5a 4f 42 58 75 77 49 6d 56 61 76 70 59 74 58 59 67 58 49 42 47 4a 42 68 } //1 LroZOBXuwImVavpYtXYgXIBGJBh
		$a_01_3 = {6e 66 4e 6b 4d 44 4b 6d 5a 62 45 53 46 42 78 5a 5a 68 62 } //1 nfNkMDKmZbESFBxZZhb
		$a_01_4 = {50 65 67 48 59 73 56 69 75 77 6d 48 4b 65 56 45 52 67 79 } //1 PegHYsViuwmHKeVERgy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}