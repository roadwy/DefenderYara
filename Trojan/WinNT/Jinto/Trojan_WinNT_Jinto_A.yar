
rule Trojan_WinNT_Jinto_A{
	meta:
		description = "Trojan:WinNT/Jinto.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {1b c0 83 d8 ff 85 c0 75 ?? 8b 4c 24 0c 0f b7 14 79 89 54 24 1c 47 3b 7c 24 10 72 } //1
		$a_02_1 = {56 57 ff 15 ?? ?? ?? ?? 8b f8 33 f6 8d 64 24 00 6a 07 8d 04 3e 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 0c 85 c0 74 ?? 46 81 fe 00 10 00 00 72 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}