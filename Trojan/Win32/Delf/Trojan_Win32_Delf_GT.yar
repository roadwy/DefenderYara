
rule Trojan_Win32_Delf_GT{
	meta:
		description = "Trojan:Win32/Delf.GT,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 61 63 6b 65 72 20 53 6f 63 69 65 74 79 20 2d 20 54 72 6f 6a 61 6e 20 43 6c 69 65 6e 74 20 2d 20 62 79 20 50 52 43 68 61 6b 61 6c } //01 00  Hacker Society - Trojan Client - by PRChakal
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_2 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 52 65 6d 6f 74 65 41 63 63 65 73 73 } //01 00  System\CurrentControlSet\Services\RemoteAccess
		$a_01_3 = {5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00  \shell\open\command
		$a_01_4 = {54 46 74 70 53 65 72 76 65 72 } //01 00  TFtpServer
		$a_01_5 = {53 65 72 76 69 64 6f 72 46 74 70 } //00 00  ServidorFtp
	condition:
		any of ($a_*)
 
}