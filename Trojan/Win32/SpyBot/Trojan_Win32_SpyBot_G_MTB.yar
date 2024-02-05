
rule Trojan_Win32_SpyBot_G_MTB{
	meta:
		description = "Trojan:Win32/SpyBot.G!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 d2 8d 0c 1f 8b c7 f7 75 18 8b 45 14 8a 04 02 32 04 0e 47 88 01 3b 7d 0c 72 } //00 00 
	condition:
		any of ($a_*)
 
}