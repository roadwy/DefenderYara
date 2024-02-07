
rule Backdoor_Win32_Phostiko_gen_A{
	meta:
		description = "Backdoor:Win32/Phostiko.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0e 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //03 00  SOFTWARE\Borland\Delphi
		$a_01_1 = {80 bb 0a 03 00 00 00 75 47 c6 06 00 8b c3 e8 92 cb fd ff 8b 83 f0 02 00 00 8b 80 90 00 00 00 e8 71 3f fe ff 48 78 67 8b 83 f0 02 00 00 8b b0 90 00 00 00 } //01 00 
		$a_00_2 = {48 65 69 2e 2e 21 20 77 68 6f 20 61 72 65 20 79 6f 75 3f } //01 00  Hei..! who are you?
		$a_00_3 = {38 7a 65 72 6f 38 78 32 } //01 00  8zero8x2
		$a_00_4 = {49 20 6b 69 63 6b 20 75 2e 2e 2e } //01 00  I kick u...
		$a_00_5 = {68 6f 73 74 69 70 6f 6b } //00 00  hostipok
	condition:
		any of ($a_*)
 
}