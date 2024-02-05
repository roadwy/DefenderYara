
rule Trojan_Win32_Quackbot{
	meta:
		description = "Trojan:Win32/Quackbot,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 d4 8a 14 3a 22 55 90 01 01 88 10 8b 55 90 01 01 47 3b 55 90 01 01 eb 90 01 01 d3 f8 8b 4d 90 01 01 29 c1 89 f0 99 f7 7d 90 01 01 0f af c8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}