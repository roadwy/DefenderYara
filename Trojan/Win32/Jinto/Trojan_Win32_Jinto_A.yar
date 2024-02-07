
rule Trojan_Win32_Jinto_A{
	meta:
		description = "Trojan:Win32/Jinto.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {50 c7 06 e5 fa ae 4f e8 90 01 04 0f af 06 8b 4d fc 0f af 4d f8 69 c9 ca 3d e0 cf 33 c1 6a 04 56 89 06 e8 90 01 04 8b 4d fc 69 c9 20 1f d9 50 90 00 } //01 00 
		$a_00_1 = {56 8b 54 24 08 8b 74 24 0c fa 0f 20 c1 8b c1 81 e1 ff ff fe ff 0f 22 c1 f0 87 32 0f 22 c0 fb 8b c6 5e c2 08 00 } //01 00 
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 5c 25 73 } //01 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\%s
		$a_00_3 = {53 65 4c 6f 61 64 44 72 69 76 65 72 50 72 69 76 69 6c 65 67 65 } //00 00  SeLoadDriverPrivilege
	condition:
		any of ($a_*)
 
}