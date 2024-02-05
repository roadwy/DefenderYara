
rule Trojan_Win32_Tnega_PRG_MTB{
	meta:
		description = "Trojan:Win32/Tnega.PRG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d f8 83 c1 01 89 4d f8 8b 55 f8 3b 55 ec 73 47 8b 45 f4 03 45 f8 8a 08 88 4d ff 8b 55 e0 03 55 e8 8a 02 88 45 fe 0f b6 4d ff c1 f9 03 0f b6 55 ff c1 e2 05 0b ca 0f b6 45 fe 33 c8 8b 55 f4 03 55 f8 88 0a 8b 45 e8 83 c0 01 99 b9 90 01 04 f7 f9 89 55 e8 eb a8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}