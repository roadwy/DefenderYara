
rule Trojan_Win32_Doina_PADY_MTB{
	meta:
		description = "Trojan:Win32/Doina.PADY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 72 72 6f 72 21 20 41 6e 6f 74 68 65 72 20 65 78 70 6c 6f 69 74 20 69 6e 73 74 61 6e 63 65 20 69 73 20 72 75 6e 6e 69 6e 67 } //1 Error! Another exploit instance is running
		$a_01_1 = {53 79 73 74 65 6d 20 69 73 20 2a 4e 4f 54 2a 20 76 75 6c 6e 61 72 61 62 6c 65 } //1 System is *NOT* vulnarable
		$a_01_2 = {53 79 73 74 65 6d 20 69 73 20 2a 56 55 4c 4e 41 52 41 42 4c 45 2a 20 2e 2e 2e 20 20 70 77 6e 69 6e 67 } //1 System is *VULNARABLE* ...  pwning
		$a_01_3 = {53 68 65 6c 6c 20 63 6f 64 65 20 65 78 65 63 75 74 65 64 2e } //1 Shell code executed.
		$a_01_4 = {47 6f 74 20 73 79 73 74 65 6d 20 70 72 69 76 69 6c 65 67 65 73 21 20 54 79 70 65 20 77 68 6f 61 6d 69 2e } //1 Got system privileges! Type whoami.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}