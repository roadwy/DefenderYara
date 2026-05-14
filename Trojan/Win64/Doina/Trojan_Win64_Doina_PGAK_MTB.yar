
rule Trojan_Win64_Doina_PGAK_MTB{
	meta:
		description = "Trojan:Win64/Doina.PGAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 63 6f 6d 6d 61 6e 64 20 22 25 73 22 } //1 powershell.exe -windowstyle Hidden -command "%s"
		$a_01_1 = {3a 5c 50 72 6f 27 2b 27 67 72 61 6d 44 61 74 61 5c 4d 69 63 72 27 2b 27 6f 73 6f 66 74 5c } //1 :\Pro'+'gramData\Micr'+'osoft\
		$a_01_2 = {53 65 74 2d 49 74 65 6d 20 56 61 72 69 61 62 6c 65 3a 34 20 27 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 27 } //1 Set-Item Variable:4 'Net.WebClient'
		$a_01_3 = {49 74 65 6d 20 56 61 72 69 61 62 6c 65 3a 2f 64 54 29 2e 56 61 6c 75 65 7c 4d 65 6d 62 65 72 29 7c 57 68 65 72 65 2d 4f 62 6a 65 63 74 7b 24 5f 2e 4e 61 6d 65 2d 6c 69 6b 65 27 2a 6e 6c 2a 67 27 7d 29 2e 4e 61 6d 65 } //1 Item Variable:/dT).Value|Member)|Where-Object{$_.Name-like'*nl*g'}).Name
		$a_03_4 = {49 74 65 6d 20 56 61 72 69 61 62 6c 65 3a 2f 64 54 29 2e 56 61 6c 75 65 2e 28 28 4c 53 20 56 61 72 69 61 62 6c 65 3a [0-03] 29 2e 56 61 6c 75 65 29 2e 49 6e 76 6f 6b 65 28 28 56 61 72 69 61 62 6c 65 20 [0-05] 20 2d 56 61 6c 75 65 4f 29 29 7c 49 45 58 } //1
		$a_03_5 = {47 65 74 2d 56 61 72 69 61 62 6c 65 20 45 2a 78 74 29 2e 56 61 6c 75 65 7c 4d 65 6d 62 65 72 29 5b [0-02] 5d 2e 4e 61 6d 65 29 7c 4d 65 6d 62 65 72 7c 57 68 65 72 65 2d 4f 62 6a 65 63 74 7b 24 5f 2e 4e 61 6d 65 2d 6c 69 6b 65 27 2a 43 6f 6d 2a 65 27 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}