
rule Trojan_Win32_Farfli_BAX_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {89 45 fc 6a 04 68 00 10 00 00 d9 6d fc df 7d f8 8b 5d f8 c1 e3 0a 53 d9 6d 0a 6a 00 ff 15 } //02 00 
		$a_01_1 = {8b cb 2b cf 8a 14 01 80 f2 62 88 10 40 4e 75 } //00 00 
	condition:
		any of ($a_*)
 
}