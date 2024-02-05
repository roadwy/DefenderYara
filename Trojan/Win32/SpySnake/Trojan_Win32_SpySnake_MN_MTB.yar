
rule Trojan_Win32_SpySnake_MN_MTB{
	meta:
		description = "Trojan:Win32/SpySnake.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 56 57 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 89 45 b0 8b 45 10 68 00 00 00 80 50 ff 15 } //05 00 
		$a_01_1 = {6a 00 8b f8 8d 45 f8 50 53 57 56 ff 15 60 01 41 00 } //00 00 
	condition:
		any of ($a_*)
 
}