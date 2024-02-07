
rule Trojan_Win32_GandCrab_B{
	meta:
		description = "Trojan:Win32/GandCrab.B,SIGNATURE_TYPE_PEHSTR,09 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 74 6f 72 2e 65 78 65 } //01 00  cmd.exe /c taskkill /f /im tor.exe
		$a_01_1 = {2e 6f 6e 69 6f 6e } //05 00  .onion
		$a_01_2 = {52 65 6c 65 61 73 65 5c 56 61 72 65 6e 79 6b 79 2e 70 64 62 } //00 00  Release\Varenyky.pdb
		$a_01_3 = {00 5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}