
rule Trojan_Win32_WarZone_A_MTB{
	meta:
		description = "Trojan:Win32/WarZone.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 3d fc 65 49 00 00 ?? ?? a1 fc 65 49 00 50 ?? ?? ?? ?? ?? 33 c0 a3 fc 65 49 00 33 c0 a3 0c 66 49 00 29 c0 a3 00 66 49 00 c7 05 08 66 49 00 ff ff ff ff c6 05 f0 1e 49 00 00 c3 } //2
		$a_03_1 = {8b 10 09 d2 74 38 8b 4a f8 49 74 32 53 50 5b 8b 42 fc ?? ?? ?? ?? ?? 50 5a 8b 03 89 13 50 8b 48 fc ?? ?? ?? ?? ?? 58 8b 48 f8 49 } //2
		$a_81_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_81_2  & 1)*1) >=5
 
}