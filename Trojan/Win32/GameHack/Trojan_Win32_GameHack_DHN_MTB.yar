
rule Trojan_Win32_GameHack_DHN_MTB{
	meta:
		description = "Trojan:Win32/GameHack.DHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 3a 5c 41 6c 6c 20 50 72 6f 4a 65 63 74 5c 49 4e 4a 45 43 54 20 42 43 5a 20 45 44 49 54 20 4e 45 57 5c 52 65 6c 65 61 73 65 5c 42 43 5a 49 4e 4a 45 43 54 4e 45 57 2e 70 64 62 } //01 00 
		$a_03_1 = {32 c1 41 88 44 15 90 02 04 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 42 83 fa 90 01 01 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}