
rule Trojan_Win32_FrameworkPOS_PA_MTB{
	meta:
		description = "Trojan:Win32/FrameworkPOS.PA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 83 c0 01 89 45 fc 83 7d fc 46 7d 16 8b 4d 08 03 4d fc 0f be 11 83 f2 4d 8b 45 08 03 45 fc 88 10 eb db } //01 00 
		$a_01_1 = {55 8b ec 51 0f b6 45 0c 33 d2 b9 08 00 00 00 f7 f1 88 55 0c 0f b6 55 08 0f b6 4d 0c d3 fa 88 55 ff 0f b6 45 08 0f b6 4d 0c ba 08 00 00 00 2b d1 8b ca d3 e0 88 45 fe 0f b6 45 ff 0f b6 4d fe 0b c1 8b e5 5d c3 } //00 00 
	condition:
		any of ($a_*)
 
}