
rule Trojan_Win32_KillProc_NS_MTB{
	meta:
		description = "Trojan:Win32/KillProc.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {b9 80 e6 44 00 e8 ?? ?? ?? ?? 8d 45 fc 50 68 06 00 02 00 6a 00 68 8c e6 44 00 68 02 00 00 80 e8 ?? ?? ?? ?? 83 7d fc 00 75 28 } //2
		$a_03_1 = {8d 55 b0 8b c6 e8 ?? ?? ?? ?? ff 75 b0 68 20 eb 44 00 8b 45 fc ff 34 d8 8d 45 b4 ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 55 b4 b8 f8 ea 44 00 e8 } //3
		$a_01_2 = {6b 69 6c 6c 31 32 33 } //1 kill123
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1) >=6
 
}