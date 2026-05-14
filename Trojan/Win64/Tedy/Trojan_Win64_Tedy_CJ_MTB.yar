
rule Trojan_Win64_Tedy_CJ_MTB{
	meta:
		description = "Trojan:Win64/Tedy.CJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 08 00 00 "
		
	strings :
		$a_01_0 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 53 74 65 61 6d } //5 AppData\Local\Steam
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c } //5 powershell
		$a_01_2 = {2d 4e 6f 50 72 6f 66 69 6c 65 } //5 -NoProfile
		$a_01_3 = {2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e } //5 -WindowStyle Hidden
		$a_01_4 = {45 78 70 61 6e 64 2d 41 72 63 68 69 76 65 20 2d 50 61 74 68 } //5 Expand-Archive -Path
		$a_01_5 = {63 6d 64 20 2f 63 20 72 6d 64 69 72 } //5 cmd /c rmdir
		$a_01_6 = {64 69 73 63 6f 72 64 2e 67 67 2f } //5 discord.gg/
		$a_01_7 = {56 65 72 69 66 69 71 75 65 20 73 75 61 20 63 6f 6e 65 78 61 6f 20 63 6f 6d 20 61 20 69 6e 74 65 72 6e 65 74 } //5 Verifique sua conexao com a internet
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5) >=40
 
}