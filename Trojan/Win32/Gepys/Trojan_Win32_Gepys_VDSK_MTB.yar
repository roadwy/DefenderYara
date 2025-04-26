
rule Trojan_Win32_Gepys_VDSK_MTB{
	meta:
		description = "Trojan:Win32/Gepys.VDSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 4d e0 8b 45 f0 8b df d3 e3 03 c7 8b f7 c1 ee 05 03 5d e4 03 75 d0 33 d8 a1 ?? ?? ?? ?? 3d 3f 0b 00 00 75 17 } //2
		$a_00_1 = {8b 55 08 8b 4d 0c 8a 02 88 45 ff 8a 01 88 02 8a 45 ff 88 01 c9 c3 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2) >=2
 
}