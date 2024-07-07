
rule Trojan_O97M_Mraitlce_A_MTB{
	meta:
		description = "Trojan:O97M/Mraitlce.A!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {3d 20 22 43 3a 5c 55 73 65 72 73 5c 22 20 26 20 47 65 74 55 73 65 72 4e 61 6d 65 20 26 20 22 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c } //1 = "C:\Users\" & GetUserName & "\AppData\Roaming\
		$a_02_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 90 02 10 2c 20 90 02 10 20 26 20 22 90 02 10 2e 62 61 74 22 2c 20 30 2c 20 30 90 00 } //3
		$a_00_2 = {53 68 65 6c 6c 20 28 22 43 3a 5c 55 73 65 72 73 5c 22 20 26 20 47 65 74 55 73 65 72 4e 61 6d 65 20 26 20 22 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 61 72 74 69 63 6c 65 2e 74 78 74 22 29 } //1 Shell ("C:\Users\" & GetUserName & "\AppData\Roaming\article.txt")
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*3+(#a_00_2  & 1)*1) >=3
 
}