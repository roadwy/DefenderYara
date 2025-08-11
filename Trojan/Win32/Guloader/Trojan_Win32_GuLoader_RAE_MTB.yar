
rule Trojan_Win32_GuLoader_RAE_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {64 65 61 66 65 6e 69 6e 67 6c 79 20 64 65 6d 6f 6e 69 66 75 67 65 } //1 deafeningly demonifuge
		$a_81_1 = {6c 65 6b 74 69 65 72 6e 65 73 20 63 65 6e 74 72 61 6c 73 6b 6f 6c 65 73 } //1 lektiernes centralskoles
		$a_81_2 = {76 65 64 65 72 68 65 66 74 69 67 68 65 64 65 72 6e 65 2e 65 78 65 } //1 vederheftighederne.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}