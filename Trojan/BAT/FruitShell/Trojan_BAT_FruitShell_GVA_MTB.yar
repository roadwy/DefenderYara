
rule Trojan_BAT_FruitShell_GVA_MTB{
	meta:
		description = "Trojan:BAT/FruitShell.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 61 70 70 6c 65 20 3d 20 24 61 70 70 6c 65 20 2d 72 65 70 6c 61 63 65 20 27 78 27 2c 20 27 2e 27 } //1 $apple = $apple -replace 'x', '.'
		$a_01_1 = {2e 57 72 69 74 65 28 28 70 77 64 29 2e 50 61 74 68 20 2b 20 27 3e 20 27 29 } //1 .Write((pwd).Path + '> ')
		$a_01_2 = {4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 53 6f 63 6b 65 74 73 2e 54 63 70 43 6c 69 65 6e 74 28 24 } //1 New-Object System.Net.Sockets.TcpClient($
		$a_01_3 = {4e 65 77 2d 4f 62 6a 65 63 74 20 49 4f 2e 53 74 72 65 61 6d 57 72 69 74 65 72 28 24 } //1 New-Object IO.StreamWriter($
		$a_01_4 = {4e 65 77 2d 4f 62 6a 65 63 74 20 49 4f 2e 53 74 72 65 61 6d 52 65 61 64 65 72 28 24 } //1 New-Object IO.StreamReader($
		$a_02_5 = {49 6e 76 6f 6b 65 2d 45 78 70 72 65 73 73 69 6f 6e 20 24 [0-20] 20 7c 20 4f 75 74 2d 53 74 72 69 6e 67 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_02_5  & 1)*1) >=6
 
}