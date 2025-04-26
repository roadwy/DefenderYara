
rule Trojan_Win32_AsyncRat_Z_MTB{
	meta:
		description = "Trojan:Win32/AsyncRat.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 66 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e 20 2f 72 6c 20 68 69 67 68 65 73 74 20 2f 74 6e } //1 schtasks /create /f /sc onlogon /rl highest /tn
		$a_81_1 = {53 74 75 62 2e 65 78 65 } //1 Stub.exe
		$a_81_2 = {67 65 74 5f 41 63 74 69 76 61 74 65 50 6f 6e 67 } //1 get_ActivatePong
		$a_81_3 = {76 6d 77 61 72 65 } //1 vmware
		$a_81_4 = {6e 75 52 5c 6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43 5c 73 77 6f 64 6e 69 57 5c 74 66 6f 73 6f 72 63 69 4d 5c 65 72 61 77 74 66 6f 53 } //1 nuR\noisreVtnerruC\swodniW\tfosorciM\erawtfoS
		$a_81_5 = {67 65 74 5f 53 73 6c 43 6c 69 65 6e 74 } //1 get_SslClient
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule Trojan_Win32_AsyncRat_Z_MTB_2{
	meta:
		description = "Trojan:Win32/AsyncRat.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 66 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e 20 2f 72 6c 20 68 69 67 68 65 73 74 20 2f 74 6e } //1 schtasks /create /f /sc onlogon /rl highest /tn
		$a_81_1 = {6e 75 52 5c 6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43 5c 73 77 6f 64 6e 69 57 5c 74 66 6f 73 6f 72 63 69 4d 5c 65 72 61 77 74 66 6f 53 } //1 nuR\noisreVtnerruC\swodniW\tfosorciM\erawtfoS
		$a_81_2 = {67 65 74 5f 53 73 6c 43 6c 69 65 6e 74 } //1 get_SslClient
		$a_81_3 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //1 Select * from AntivirusProduct
		$a_81_4 = {67 65 74 5f 54 63 70 43 6c 69 65 6e 74 } //1 get_TcpClient
		$a_81_5 = {67 65 74 5f 53 65 6e 64 53 79 6e 63 } //1 get_SendSync
		$a_81_6 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
		$a_81_7 = {74 69 6d 65 6f 75 74 } //1 timeout
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}