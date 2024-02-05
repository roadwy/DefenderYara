
rule Trojan_Win32_Swisyn_MBHW_MTB{
	meta:
		description = "Trojan:Win32/Swisyn.MBHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 3e 40 00 01 f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 02 00 01 00 e9 00 00 00 74 3b 40 00 14 3c 40 00 18 29 40 00 78 00 00 00 83 00 00 00 8c } //01 00 
		$a_01_1 = {41 00 2a 00 5c 00 41 00 46 00 3a 00 5c 00 52 00 46 00 44 00 5c 00 78 00 4e 00 65 00 77 00 43 00 6f 00 64 00 65 00 5c 00 78 00 4e 00 65 00 77 00 50 } //00 00 
	condition:
		any of ($a_*)
 
}