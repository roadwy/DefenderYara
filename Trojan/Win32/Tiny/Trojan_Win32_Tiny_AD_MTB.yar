
rule Trojan_Win32_Tiny_AD_MTB{
	meta:
		description = "Trojan:Win32/Tiny.AD!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 45 08 0f be 08 88 4d ff 8b 45 08 89 c1 40 89 45 08 8b 45 f8 0f be 10 88 11 8b 45 f8 0f be 4d ff 88 08 } //0a 00 
		$a_01_1 = {88 45 99 b8 20 00 00 00 88 45 9a b8 64 00 00 00 88 45 9b b8 6d 00 00 00 88 45 9c b8 63 00 00 00 88 45 9d } //00 00 
	condition:
		any of ($a_*)
 
}