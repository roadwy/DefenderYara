
rule _PseudoThreat_40000020{
	meta:
		description = "!PseudoThreat_40000020,SIGNATURE_TYPE_PEHSTR_EXT,2b 00 28 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 6c 69 65 6e 74 20 49 50 2d 49 50 58 } //10 Client IP-IPX
		$a_01_1 = {30 30 30 30 7d 5c 55 70 64 61 74 65 2e 65 78 65 2e 6c 7a 6d 61 } //10 0000}\Update.exe.lzma
		$a_01_2 = {73 76 63 68 6f 73 74 73 } //5 svchosts
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e } //5 Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
		$a_01_4 = {48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 5c 43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 } //5 HARDWARE\DESCRIPTION\System\CentralProcessor\0
		$a_01_5 = {56 69 64 65 6f 42 69 6f 73 44 61 74 65 00 00 00 53 79 73 74 65 6d 42 69 6f 73 44 61 74 65 } //5
		$a_01_6 = {25 30 34 64 00 00 00 00 2d 00 00 00 25 30 34 58 00 00 00 00 7e 4d 68 7a 00 } //3
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*3) >=40
 
}