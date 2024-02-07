
rule Trojan_Win32_Vbservpy_A_bit{
	meta:
		description = "Trojan:Win32/Vbservpy.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2a 00 5c 00 41 00 44 00 3a 00 5c 00 4d 00 49 00 48 00 41 00 49 00 4c 00 4f 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 5c 00 4d 00 6f 00 6a 00 65 00 5c 00 4c 00 69 00 66 00 65 00 34 00 48 00 61 00 63 00 6b 00 20 00 52 00 41 00 54 00 5c 00 52 00 61 00 74 00 5c 00 53 00 65 00 72 00 76 00 65 00 72 00 } //01 00  *\AD:\MIHAILO\Programs\Moje\Life4Hack RAT\Rat\Server
		$a_01_1 = {73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 20 00 2d 00 73 00 20 00 2d 00 74 00 20 00 30 00 30 00 } //01 00  shutdown -s -t 00
		$a_01_2 = {73 00 65 00 72 00 76 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00  server.exe
	condition:
		any of ($a_*)
 
}