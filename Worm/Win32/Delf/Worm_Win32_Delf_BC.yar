
rule Worm_Win32_Delf_BC{
	meta:
		description = "Worm:Win32/Delf.BC,SIGNATURE_TYPE_PEHSTR,35 00 35 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 53 41 52 65 63 76 45 78 } //0a 00  WSARecvEx
		$a_01_1 = {54 72 61 6e 73 6d 69 74 46 69 6c 65 } //0a 00  TransmitFile
		$a_01_2 = {41 63 6c 6f 6d 65 72 6c 6f 67 40 67 6d 61 69 6c 2e 63 6f 6d } //0a 00  Aclomerlog@gmail.com
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_4 = {4c 6f 67 73 20 79 20 63 61 70 74 75 72 61 73 20 76 69 65 6e 65 6e 20 61 64 6a 75 6e 74 61 64 6f 73 } //01 00  Logs y capturas vienen adjuntados
		$a_01_5 = {25 73 79 73 64 69 72 25 } //01 00  %sysdir%
		$a_01_6 = {6d 73 6b 79 5c 6c 6f 67 73 5c 6b 79 6c 2a } //01 00  msky\logs\kyl*
		$a_01_7 = {6d 73 6b 79 5c 63 6c 69 63 6b 73 68 6f 74 73 5c 6b 79 63 2a } //01 00  msky\clickshots\kyc*
		$a_01_8 = {2f 6c 61 6e 7a 61 74 65 52 75 6e 4f 6e 63 65 } //01 00  /lanzateRunOnce
		$a_01_9 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 41 } //00 00  InternetConnectA
	condition:
		any of ($a_*)
 
}