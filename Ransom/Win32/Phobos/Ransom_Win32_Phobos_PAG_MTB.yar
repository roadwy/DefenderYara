
rule Ransom_Win32_Phobos_PAG_MTB{
	meta:
		description = "Ransom:Win32/Phobos.PAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c2 8d 4c 24 ?? e8 ?? ?? ?? ?? 8b 4c 24 18 8b f2 d3 ee 8b 4c 24 10 03 cb 8d 04 17 33 c8 03 f5 81 3d } //1
		$a_03_1 = {8d 14 37 d3 ee 8b 4c 24 ?? 8d 44 24 ?? 89 54 24 ?? 89 74 24 1c c7 05 ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 44 24 28 31 44 24 10 81 3d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}