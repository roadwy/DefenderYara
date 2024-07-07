
rule Trojan_BAT_Nanobot_RM_MTB{
	meta:
		description = "Trojan:BAT/Nanobot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 "
		
	strings :
		$a_81_0 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_1 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_2 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 } //1 SecurityProtocolType
		$a_81_3 = {43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 47 55 49 4d 69 6e 65 73 77 65 65 70 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 47 55 49 4d 69 6e 65 73 77 65 65 70 65 72 2e 70 64 62 } //10 C:\Users\Administrator\Desktop\GUIMinesweeper\obj\Debug\GUIMinesweeper.pdb
		$a_81_4 = {68 74 74 70 3a 2f 2f 70 61 73 74 65 78 2e 70 72 6f 2f 62 2f 4e 65 62 41 51 72 43 7a 67 } //10 http://pastex.pro/b/NebAQrCzg
		$a_81_5 = {59 6f 75 20 6c 6f 73 65 } //1 You lose
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*10+(#a_81_4  & 1)*10+(#a_81_5  & 1)*1) >=24
 
}