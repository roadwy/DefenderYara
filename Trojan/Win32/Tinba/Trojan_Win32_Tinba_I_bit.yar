
rule Trojan_Win32_Tinba_I_bit{
	meta:
		description = "Trojan:Win32/Tinba.I!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 85 ad ff b3 e8 ?? ?? ?? 00 89 45 fc 8b 4d fc 68 ab 9b e1 ab 51 e8 ?? ?? ?? 00 83 c4 08 89 45 f8 6a 40 68 00 10 00 00 68 ?? ?? ?? 00 6a 00 ff 55 f8 89 45 fc 68 9c ea 25 e4 68 ?? ?? ?? 00 68 ?? ?? ?? 00 ff 75 fc e8 ?? ?? ?? 00 ff 55 fc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}