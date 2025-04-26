
rule Trojan_Win32_ChChes_A_dha{
	meta:
		description = "Trojan:Win32/ChChes.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 55 0c 8b 4d 08 2b d1 56 57 6a 04 5e 6a 04 5f 8a 04 0a 30 01 41 83 ef 01 75 ?? 83 ee 01 75 } //1
		$a_03_1 = {56 57 8b 7d 08 6a ?? 59 6a ?? 5a 33 f6 8d 04 32 25 ?? ?? ?? ?? 79 ?? 48 83 c8 ?? 40 03 c1 8a 04 38 88 44 35 08 46 83 fe ?? 7c ?? 8b 45 08 4a 89 04 39 83 c1 ?? 85 d2 7f ?? 5f 5e } //1
		$a_00_2 = {52 65 6c 65 61 73 65 5c 48 75 79 61 } //-2 Release\Huya
		$a_00_3 = {68 79 64 65 76 69 63 65 2e 70 64 62 } //-2 hydevice.pdb
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*-2+(#a_00_3  & 1)*-2) >=2
 
}