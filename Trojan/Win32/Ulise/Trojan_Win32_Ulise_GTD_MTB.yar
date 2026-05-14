
rule Trojan_Win32_Ulise_GTD_MTB{
	meta:
		description = "Trojan:Win32/Ulise.GTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e2 0d 33 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? c1 e8 11 33 05 } //5
		$a_01_1 = {c6 45 fc 4e c6 45 fd 74 c6 45 fe 00 c6 45 d0 43 c6 45 d1 72 c6 45 d2 65 c6 45 d3 61 c6 45 d4 74 c6 45 d5 65 c6 45 d6 00 c6 45 d8 46 c6 45 d9 69 c6 45 da 6c c6 45 db 65 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}