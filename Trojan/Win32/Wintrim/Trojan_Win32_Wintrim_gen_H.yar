
rule Trojan_Win32_Wintrim_gen_H{
	meta:
		description = "Trojan:Win32/Wintrim.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {4d 43 76 32 44 4c 4c 2e 64 6c 6c 00 53 74 61 72 74 4d 43 00 } //01 00  䍍㉶䱄⹌汤l瑓牡䵴C
		$a_01_1 = {e9 dd 07 00 00 55 8b ec 83 ec 34 8b 45 08 8b 48 08 33 d2 42 53 8b 58 0c 56 8b f2 d3 e6 8b 48 04 8b 00 57 8b fa d3 e7 89 45 d4 03 c8 b8 00 03 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}