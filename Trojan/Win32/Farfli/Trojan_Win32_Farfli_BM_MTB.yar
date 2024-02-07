
rule Trojan_Win32_Farfli_BM_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 83 c0 01 89 45 f8 8b 4d f8 3b 4d 0c 73 29 8b 55 08 03 55 f8 33 c0 8a 02 8b 4d fc 33 c8 81 e1 ff 00 00 00 8b 55 fc c1 ea 08 8b 04 8d 90 02 04 33 c2 89 45 fc eb 90 00 } //01 00 
		$a_01_1 = {61 64 6d 69 6e 64 2e 66 33 33 32 32 2e 6e 65 74 } //00 00  admind.f3322.net
	condition:
		any of ($a_*)
 
}