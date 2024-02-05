
rule Trojan_Win32_VBKrypt_BG_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 07 00 00 01 00 "
		
	strings :
		$a_02_0 = {ff 34 0a 39 c2 90 02 4f 81 f7 90 02 1f 89 3c 08 90 02 1f 83 e9 04 7d 90 02 1f ff d0 90 00 } //01 00 
		$a_02_1 = {ff 34 0a 39 c1 90 02 4f 81 f7 90 02 1f 89 3c 08 90 02 1f 83 e9 04 7d 90 02 1f ff d0 90 00 } //01 00 
		$a_02_2 = {ff 34 0a 39 c6 90 02 4f 81 f7 90 02 1f 89 3c 08 90 02 1f 83 e9 04 7d 90 02 1f ff d0 90 00 } //01 00 
		$a_02_3 = {ff 34 0a 39 c3 90 02 4f 81 f7 90 02 1f 89 3c 08 90 02 1f 83 e9 04 7d 90 02 1f ff d0 90 00 } //01 00 
		$a_02_4 = {ff 34 0a 39 c7 90 02 4f 81 f7 90 02 1f 89 3c 08 90 02 1f 83 e9 04 7d 90 02 1f ff d0 90 00 } //01 00 
		$a_02_5 = {ff 34 0a 39 d0 90 02 4f 81 f7 90 02 1f 89 3c 08 90 02 1f 83 e9 04 7d 90 02 1f ff d0 90 00 } //01 00 
		$a_02_6 = {39 c6 ff 34 0a 90 02 4f 81 f7 90 02 1f 89 3c 08 90 02 1f 83 e9 04 7d 90 02 1f ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}