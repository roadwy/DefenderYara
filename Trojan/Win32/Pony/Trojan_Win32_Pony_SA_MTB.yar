
rule Trojan_Win32_Pony_SA_MTB{
	meta:
		description = "Trojan:Win32/Pony.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {ab 44 02 cb 8b fe 1a 65 1b 34 90 01 01 57 42 c3 90 00 } //01 00 
		$a_02_1 = {8b f2 b0 83 4e 44 b2 31 97 f0 08 0e b1 90 0a 10 00 8b f2 b0 90 01 01 4e 44 b2 90 01 01 97 90 02 0a f0 08 0e b1 90 01 01 23 c9 d4 90 01 01 43 23 57 7c 80 38 90 01 01 5f 8a 3b 4d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}