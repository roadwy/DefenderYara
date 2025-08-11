
rule Trojan_Win32_Nanocore_BAA_MTB{
	meta:
		description = "Trojan:Win32/Nanocore.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 31 8d 49 01 34 ?? 88 41 ff 83 ef 01 75 } //2
		$a_03_1 = {2a c8 8b 45 08 0a d1 8b 4d e8 8b 00 88 14 01 41 89 4d e8 81 ff ?? ?? ?? ?? 72 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}