
rule Trojan_Win32_Fnddos{
	meta:
		description = "Trojan:Win32/Fnddos,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 57 77 2e 4d 6d 44 6f 53 2e 43 6e } //01 00  wWw.MmDoS.Cn
		$a_01_1 = {44 61 73 44 4e 46 31 31 31 } //01 00  DasDNF111
		$a_01_2 = {54 00 72 00 6f 00 6a 00 61 00 6e 00 2e 00 57 00 69 00 6e 00 33 00 32 00 2e 00 4f 00 6e 00 6c 00 69 00 6e 00 65 00 47 00 61 00 6d 00 65 00 73 00 2e 00 44 00 61 00 73 00 44 00 4e 00 46 00 } //00 00  Trojan.Win32.OnlineGames.DasDNF
	condition:
		any of ($a_*)
 
}