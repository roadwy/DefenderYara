
rule Trojan_Win32_Udochka_BH_MTB{
	meta:
		description = "Trojan:Win32/Udochka.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 8b d3 03 c6 3b c7 7c 03 8b 55 08 33 c9 85 d2 7e 0c 8a 44 0d f0 30 04 0e 41 3b ca 7c f4 29 5d 08 03 f3 ff 4d fc 75 d6 } //00 00 
	condition:
		any of ($a_*)
 
}