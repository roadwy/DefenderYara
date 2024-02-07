
rule Backdoor_Win32_Nupic_A{
	meta:
		description = "Backdoor:Win32/Nupic.A,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {61 63 63 65 73 6f 70 64 } //0a 00  accesopd
		$a_01_1 = {55 4e 49 51 55 41 57 49 2a } //01 00  UNIQUAWI*
		$a_00_2 = {50 4f 53 54 20 68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 6e 65 74 2f 42 25 73 2f 73 65 72 69 6e 66 6f 20 48 54 54 50 2f 31 2e 31 } //01 00  POST http://%s:%d/net/B%s/serinfo HTTP/1.1
		$a_00_3 = {6e 4e 65 77 73 4e 6e } //01 00  nNewsNn
		$a_00_4 = {25 73 20 68 74 74 70 3a 2f 2f 61 62 6f 75 74 3a 62 6c 61 6e 6b } //01 00  %s http://about:blank
		$a_00_5 = {68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //00 00  http\shell\open\command
	condition:
		any of ($a_*)
 
}