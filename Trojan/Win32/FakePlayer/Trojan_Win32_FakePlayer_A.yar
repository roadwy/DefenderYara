
rule Trojan_Win32_FakePlayer_A{
	meta:
		description = "Trojan:Win32/FakePlayer.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f 85 c2 00 00 00 80 7d 90 01 01 47 0f 85 90 01 02 00 00 80 7d 90 01 01 49 0f 85 90 01 02 00 00 80 7d 90 01 01 46 0f 85 90 01 02 00 00 80 7d 90 01 01 38 0f 85 90 01 02 00 00 90 00 } //02 00 
		$a_03_1 = {75 09 80 81 90 01 03 00 fd eb 33 8b c1 6a 03 99 5f f7 ff 85 d2 75 08 fe 89 90 01 03 00 eb 1f 90 00 } //01 00 
		$a_00_2 = {5c 4d 79 49 45 44 61 74 61 5c 6d 61 69 6e 2e 69 6e 69 } //00 00 
	condition:
		any of ($a_*)
 
}