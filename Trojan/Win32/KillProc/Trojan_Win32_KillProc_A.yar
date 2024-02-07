
rule Trojan_Win32_KillProc_A{
	meta:
		description = "Trojan:Win32/KillProc.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {83 f8 05 7e 20 80 3e 70 75 1b 80 7e 01 63 75 15 80 7c 30 fd 72 75 0e 80 7c 30 fe 65 75 07 80 7c 30 ff 67 74 0b } //0a 00 
		$a_02_1 = {8a 1c 0e 32 9a 90 01 03 10 83 c2 01 3b d5 88 5c 0e ff 75 02 33 d2 83 c1 01 3b cf 7e e3 90 00 } //01 00 
		$a_00_2 = {43 6f 6e 64 69 74 69 6f 6e 61 6c 4b 69 6c 6c 65 72 2e 64 6c 6c } //01 00  ConditionalKiller.dll
		$a_00_3 = {54 72 61 6e 73 61 63 74 4e 61 6d 65 64 50 69 70 65 } //00 00  TransactNamedPipe
	condition:
		any of ($a_*)
 
}