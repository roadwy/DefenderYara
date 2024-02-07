
rule Worm_Win32_Brizol{
	meta:
		description = "Worm:Win32/Brizol,SIGNATURE_TYPE_PEHSTR,09 00 07 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 41 49 4c 20 46 52 4f 4d 3a 20 3c 25 73 3e } //01 00  MAIL FROM: <%s>
		$a_01_1 = {52 43 50 54 20 54 4f 3a 20 3c 25 73 3e } //01 00  RCPT TO: <%s>
		$a_01_2 = {5c 73 63 61 6e 73 76 63 5c 74 72 75 73 74 } //01 00  \scansvc\trust
		$a_01_3 = {40 62 6c 61 63 6b 68 6f 74 6d 61 69 6c 2e 63 6f 6d } //01 00  @blackhotmail.com
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 5c 25 73 } //01 00  Software\Microsoft\Internet Account Manager\Accounts\%s
		$a_01_5 = {5c 6f 66 66 69 63 65 70 61 72 61 6d 2e 64 6c 6c } //01 00  \officeparam.dll
		$a_01_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_7 = {4d 4f 44 45 4d } //01 00  MODEM
		$a_01_8 = {2e 4e 45 54 00 00 00 00 2e 6e 65 74 00 00 00 00 2e 43 4f 4d 00 00 00 00 2e 63 6f 6d 00 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}