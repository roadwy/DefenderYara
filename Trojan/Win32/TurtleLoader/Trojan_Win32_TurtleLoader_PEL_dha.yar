
rule Trojan_Win32_TurtleLoader_PEL_dha{
	meta:
		description = "Trojan:Win32/TurtleLoader.PEL!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 00 69 00 6e 00 48 00 54 00 54 00 50 00 20 00 45 00 78 00 61 00 6d 00 70 00 6c 00 65 00 2f 00 31 00 2e 00 30 00 } //01 00  WinHTTP Example/1.0
		$a_01_1 = {46 61 69 6c 65 64 20 69 6e 20 72 65 74 72 69 65 76 69 6e 67 20 74 68 65 20 53 68 65 6c 6c 63 6f 64 65 } //01 00  Failed in retrieving the Shellcode
		$a_01_2 = {5b 2b 5d 20 44 65 63 72 79 70 74 20 74 68 65 20 50 45 } //00 00  [+] Decrypt the PE
	condition:
		any of ($a_*)
 
}