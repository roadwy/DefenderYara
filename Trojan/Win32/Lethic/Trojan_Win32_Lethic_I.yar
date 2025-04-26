
rule Trojan_Win32_Lethic_I{
	meta:
		description = "Trojan:Win32/Lethic.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 89 01 68 ?? ?? ?? ?? 8b 55 ?? 52 ff 15 ?? ?? ?? ?? 8b 4d 08 89 41 04 } //1
		$a_03_1 = {8b 55 08 8b 82 ?? 01 00 00 ff d0 3d 33 27 00 00 75 0f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}