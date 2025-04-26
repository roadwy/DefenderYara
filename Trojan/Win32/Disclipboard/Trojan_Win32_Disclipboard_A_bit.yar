
rule Trojan_Win32_Disclipboard_A_bit{
	meta:
		description = "Trojan:Win32/Disclipboard.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {31 44 35 55 44 63 57 38 52 55 65 56 74 58 65 46 45 6a 6b 39 39 4b 64 66 64 77 37 6b 7a 35 4e 68 79 78 } //1 1D5UDcW8RUeVtXeFEjk99Kdfdw7kz5Nhyx
		$a_01_2 = {4c 4e 37 73 53 77 39 7a 78 79 50 72 45 4b 4d 55 4b 78 50 46 53 4b 41 4a 53 32 50 32 4c 4b 74 6b 79 59 } //1 LN7sSw9zxyPrEKMUKxPFSKAJS2P2LKtkyY
		$a_01_3 = {50 47 35 6b 42 35 54 50 57 4c 4c 52 38 79 31 47 33 64 6a 35 4e 6d 57 65 5a 38 66 67 73 41 62 54 71 71 } //1 PG5kB5TPWLLR8y1G3dj5NmWeZ8fgsAbTqq
		$a_01_4 = {58 6b 54 62 61 62 55 78 6d 65 68 66 72 66 48 51 55 78 53 76 57 42 38 74 59 38 59 66 7a 58 4b 6a 48 58 } //1 XkTbabUxmehfrfHQUxSvWB8tY8YfzXKjHX
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}