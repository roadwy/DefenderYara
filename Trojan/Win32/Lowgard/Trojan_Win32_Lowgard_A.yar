
rule Trojan_Win32_Lowgard_A{
	meta:
		description = "Trojan:Win32/Lowgard.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4f 00 73 00 72 00 61 00 42 00 63 00 4c 00 75 00 50 00 47 00 } //1 OsraBcLuPG
		$a_03_1 = {8d 4d c0 ba ?? ?? 52 00 8b 45 fc e8 ?? ?? ?? ?? 8b 45 c0 e8 ?? ?? ?? ?? 50 6a 00 6a 00 e8 ?? ?? ?? ?? 6a 00 8d 4d b8 ba ?? ?? 52 00 8b 45 fc e8 ?? ?? ?? ?? ff 75 b8 68 ?? ?? 52 00 68 ?? ?? 52 00 8d 45 bc ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 4d bc ba ?? ?? 52 00 8b 45 fc e8 ?? ?? ?? ?? 8d 4d b0 ba ?? ?? 52 00 8b 45 fc e8 ?? ?? ?? ?? ff 75 b0 68 ?? ?? 52 00 68 ?? ?? 52 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}