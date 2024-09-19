
rule Trojan_Win32_BlackMoon_GLY_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.GLY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {af b3 04 00 83 ?? ?? ?? ?? 00 00 00 8b ?? ?? ?? ?? 00 55 8b ec e8 ?? ?? ?? ?? 8b e5 5d c3 55 8b ec 81 ec 04 00 00 00 89 65 fc 68 00 00 00 00 } //10
		$a_01_1 = {6e 48 59 62 47 56 66 47 57 64 4b } //1 nHYbGVfGWdK
		$a_01_2 = {62 6c 61 63 6b 6d 6f 6f 6e } //1 blackmoon
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}