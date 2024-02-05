
rule Trojan_Win32_NSISInject_FD_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.FD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 8b d8 53 6a 00 ff 15 } //0a 00 
		$a_01_1 = {6a 40 68 00 30 00 00 8b 4d e8 51 6a 00 ff 15 } //01 00 
		$a_01_2 = {53 68 80 00 00 00 6a 03 53 6a 07 68 00 00 00 80 ff 75 10 ff 15 } //01 00 
		$a_01_3 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 b8 04 00 00 00 c1 e0 00 8b 4d e0 8b 14 01 52 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}