
rule Trojan_Win32_FakeMadoc{
	meta:
		description = "Trojan:Win32/FakeMadoc,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {2a 00 2e 00 2a 00 00 00 2e 00 65 00 78 00 65 00 00 00 00 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 2e 00 73 00 79 00 73 00 00 00 } //01 00 
		$a_03_1 = {6a 64 ff 15 90 01 04 eb 2f 66 83 7c 24 90 01 01 2e 75 18 66 83 7c 24 90 01 01 00 74 1f 66 83 7c 24 90 01 01 2e 75 08 66 83 7c 24 90 01 01 00 74 0f 90 00 } //01 00 
		$a_01_2 = {6a 00 6a 64 68 37 12 00 00 ff 73 08 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}