
rule Trojan_Win32_Koobface_gen_P{
	meta:
		description = "Trojan:Win32/Koobface.gen!P,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4f 04 83 c7 04 85 c9 89 7c 24 ?? 8b c7 0f 85 ?? ?? ?? ?? eb ?? 56 } //1
		$a_01_1 = {3f 61 63 74 69 6f 6e 3d 70 6c 67 65 6e } //1 ?action=plgen
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}