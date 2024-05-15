
rule Trojan_Win64_SpyGo_MR_MTB{
	meta:
		description = "Trojan:Win64/SpyGo.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_80_0 = {6b 65 79 6c 6f 67 20 73 65 6e 74 2e 20 4b 65 79 6c 6f 67 } //keylog sent. Keylog  01 00 
		$a_01_1 = {48 8d 15 c5 2c 0e 00 48 89 54 24 30 e8 1b 41 de ff 48 8d 0d 34 af 01 00 48 89 4c 24 38 48 89 44 24 40 48 8b 1d 6b ff 26 00 48 8d 05 3c 3d 0e 00 48 8d 4c 24 28 bf 02 00 00 00 48 89 fe e8 4a 47 e9 ff 31 c0 48 8d 1d 9c 77 07 00 } //00 00 
	condition:
		any of ($a_*)
 
}