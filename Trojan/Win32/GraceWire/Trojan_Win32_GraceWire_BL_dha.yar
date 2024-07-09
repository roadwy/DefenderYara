
rule Trojan_Win32_GraceWire_BL_dha{
	meta:
		description = "Trojan:Win32/GraceWire.BL!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {c7 45 fc 00 00 00 00 8b 45 08 33 45 0c 89 45 08 c1 45 08 04 8b 4d 08 81 c1 78 77 77 77 89 4d 08 8b 45 08 } //2
		$a_02_1 = {c7 45 fc 00 00 00 00 8b 45 08 33 45 0c 89 45 08 c1 45 08 04 8b 4d 08 81 c1 ?? ?? ?? ?? 89 4d 08 8b 45 08 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*1) >=2
 
}