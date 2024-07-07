
rule TrojanDownloader_O97M_Obfuse_PXZR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PXZR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 61 73 65 62 61 6c 6c 2e 63 6f 6e 66 65 73 73 69 6f 6e 61 72 69 65 73 56 69 6c 6e 69 75 73 20 28 22 54 65 6d 70 22 29 } //1 baseball.confessionariesVilnius ("Temp")
		$a_01_1 = {43 61 6c 6c 20 63 6f 70 69 74 61 73 50 69 63 61 72 64 28 22 43 6c 61 72 65 61 63 63 69 64 65 6e 63 65 22 2c 20 22 53 61 6d 6e 69 74 65 63 6f 6d 6d 75 6e 61 6c 69 73 61 74 69 6f 6e 22 2c 20 22 63 68 69 6c 6c 79 22 29 } //1 Call copitasPicard("Clareaccidence", "Samnitecommunalisation", "chilly")
		$a_01_2 = {27 4d 73 67 42 6f 78 20 22 76 65 72 3a 22 20 26 20 76 65 72 20 26 20 22 20 74 6f 74 3a 20 22 20 26 20 74 6f 74 62 79 20 26 20 22 20 64 61 74 3a 22 20 26 20 28 74 6f 74 62 79 20 2d 20 63 63 73 69 7a 20 2a 20 63 63 62 6c 6b 73 29 20 26 20 22 20 6e 65 65 64 3a 22 20 26 20 6a } //1 'MsgBox "ver:" & ver & " tot: " & totby & " dat:" & (totby - ccsiz * ccblks) & " need:" & j
		$a_01_3 = {44 65 62 79 65 62 61 63 6b 73 70 61 63 65 73 63 6f 6c 6c 65 67 69 61 74 65 20 3d 20 45 6e 76 69 72 6f 6e 28 63 6f 6e 66 65 73 73 69 6f 6e 61 72 69 65 73 29 } //1 Debyebackspacescollegiate = Environ(confessionaries)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}