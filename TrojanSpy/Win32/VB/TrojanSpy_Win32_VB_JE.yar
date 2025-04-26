
rule TrojanSpy_Win32_VB_JE{
	meta:
		description = "TrojanSpy:Win32/VB.JE,SIGNATURE_TYPE_PEHSTR_EXT,ffffffd0 07 ffffffd0 07 02 00 00 "
		
	strings :
		$a_02_0 = {56 50 ff d7 8b 45 e0 50 68 ?? ?? 40 00 eb 5a 85 c0 75 0c 68 ?? ?? 40 00 68 ?? ?? 40 00 ff d3 8b 35 ?? ?? 40 00 8b 0e 8d 55 d8 52 56 ff 51 14 db e2 85 c0 7d 0b 6a 14 68 ?? ?? 40 00 56 50 ff d7 8b 45 d8 8b f0 8b 08 8d 55 e0 52 50 ff 51 50 db e2 85 c0 7d 0b 6a 50 68 ?? ?? 40 00 56 50 ff d7 8b 45 e0 50 68 ?? ?? 40 00 } //1000
		$a_02_1 = {ff 15 30 10 40 00 8b d0 8d 4d dc ff 15 fc 10 40 00 50 6a 01 6a ff 6a 01 ff 15 bc 10 40 00 8d 4d dc 51 8d 55 e0 52 6a 02 ff 15 d0 10 40 00 83 c4 0c 8d 4d d8 ff 15 10 11 40 00 8b 45 08 8d 70 34 6a 01 56 ff 15 14 10 40 00 ff 15 4c 10 40 00 8b 0e 51 6a 00 ff 15 74 10 40 00 85 c0 75 1a ba ?? ?? 40 00 8b ce eb 0b ba ?? ?? 40 00 8b 45 08 8d 48 34 } //1000
	condition:
		((#a_02_0  & 1)*1000+(#a_02_1  & 1)*1000) >=2000
 
}