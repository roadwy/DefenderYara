
rule Trojan_Win32_CryptInject_BK_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {b8 48 c0 00 00 01 85 d0 f3 ff ff 83 85 d0 f3 ff ff 7b 8b 85 d0 f3 ff ff 8a 4c 30 85 a1 90 01 04 88 0c 06 81 3d 90 01 04 cb 0c 00 00 75 90 00 } //01 00 
		$a_02_1 = {b8 6b fa 03 00 01 85 18 fe ff ff a1 90 01 04 03 85 1c fe ff ff 8b 8d 18 fe ff ff 03 8d 1c fe ff ff 8a 09 88 08 eb 90 00 } //01 00 
		$a_02_2 = {8a 8c 10 85 c5 0a 00 a1 90 01 04 88 0c 10 42 a1 90 01 04 3b d0 72 e2 90 00 } //01 00 
		$a_00_3 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b c1 c1 e8 10 30 04 1e 46 3b f7 7c } //00 00 
	condition:
		any of ($a_*)
 
}