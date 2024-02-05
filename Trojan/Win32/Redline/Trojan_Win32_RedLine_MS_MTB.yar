
rule Trojan_Win32_RedLine_MS_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {88 04 0f 81 3d 90 01 08 75 90 01 01 68 90 01 04 56 56 ff 15 90 01 04 47 3b 3d 90 01 04 72 90 00 } //0a 00 
		$a_01_1 = {6c 61 72 65 6c 61 6c 75 6b 6f 78 69 79 6f 74 75 6a 61 78 61 6a 69 72 6f 78 75 79 } //0a 00 
		$a_01_2 = {b8 fc d8 6a 54 f7 65 ac 8b 45 ac 81 45 b4 62 8f d8 2c b8 26 19 23 63 f7 65 b4 8b 45 b4 81 85 40 ff ff ff 79 c3 29 41 81 6d ac 04 f7 4b 79 81 6d d8 04 b1 b7 69 b8 c4 97 c3 79 f7 a5 40 ff ff ff 8b 85 40 ff ff ff b8 da 98 b4 18 f7 65 d8 8b 45 d8 b8 f7 39 ab 6d f7 65 ac 8b 45 ac b8 cd cd 54 66 f7 a5 40 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}