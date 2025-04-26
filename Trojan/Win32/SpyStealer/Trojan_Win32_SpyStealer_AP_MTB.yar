
rule Trojan_Win32_SpyStealer_AP_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 75 14 8b 45 08 0f be 34 10 68 [0-04] 68 [0-04] e8 [0-04] 83 c4 08 0f af f0 89 75 f4 8b 4d 0c 03 4d f8 8a 11 88 55 ff 0f b6 45 ff 33 45 f4 8b 4d 0c 03 4d f8 88 01 eb ac } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}