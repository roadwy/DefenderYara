
rule Trojan_Win32_Delf_KP{
	meta:
		description = "Trojan:Win32/Delf.KP,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {7b 38 46 43 35 46 37 37 39 2d 41 35 42 33 2d 32 31 37 35 39 2d 39 43 38 31 2d 39 46 42 30 31 30 45 30 31 43 42 43 7d } //04 00  {8FC5F779-A5B3-21759-9C81-9FB010E01CBC}
		$a_01_1 = {66 69 25 73 5c 25 73 63 64 75 2e 64 6c 6c } //01 00  fi%s\%scdu.dll
		$a_01_2 = {54 53 74 61 72 74 54 68 72 65 61 64 } //00 00  TStartThread
	condition:
		any of ($a_*)
 
}