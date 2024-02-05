
rule Trojan_Win32_Donvba_A{
	meta:
		description = "Trojan:Win32/Donvba.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 00 74 00 44 00 32 00 46 00 39 00 78 00 67 00 59 00 4c 00 78 00 33 00 44 00 33 00 52 00 47 00 76 00 70 00 65 00 6b 00 4c 00 58 00 4a 00 4c 00 74 00 43 00 55 00 46 00 30 00 4c 00 30 00 6f 00 31 00 7a 00 31 00 45 00 } //00 00 
	condition:
		any of ($a_*)
 
}