
rule Trojan_BAT_Aenjaris_AEN_MTB{
	meta:
		description = "Trojan:BAT/Aenjaris.AEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 72 76 65 72 6a 61 72 76 69 73 2e 73 79 74 65 73 2e 6e 65 74 } //5 serverjarvis.sytes.net
		$a_01_1 = {4e 00 4f 00 43 00 52 00 45 00 41 00 54 00 45 00 46 00 4f 00 4c 00 44 00 45 00 52 00 } //3 NOCREATEFOLDER
		$a_01_2 = {55 00 4e 00 4b 00 49 00 4c 00 41 00 42 00 4c 00 45 00 } //2 UNKILABLE
		$a_01_3 = {61 64 64 20 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 22 20 2f 76 20 22 4b 65 79 62 6f 72 64 44 72 69 76 65 72 22 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 } //4 add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "KeybordDriver" /t REG_SZ /d
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*4) >=14
 
}