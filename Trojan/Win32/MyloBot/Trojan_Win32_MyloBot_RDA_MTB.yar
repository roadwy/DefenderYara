
rule Trojan_Win32_MyloBot_RDA_MTB{
	meta:
		description = "Trojan:Win32/MyloBot.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 } //01 00  SOFTWARE\Policies\Microsoft\Windows Defender
		$a_01_1 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //02 00  DisableAntiSpyware
		$a_01_2 = {0f b6 06 33 c1 c1 e9 08 0f b6 c0 33 8c 85 00 fc ff ff 46 83 ea 01 } //02 00 
		$a_03_3 = {0f b6 06 33 c1 c1 e9 08 0f b6 c0 33 0c 85 90 01 04 46 83 ea 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}