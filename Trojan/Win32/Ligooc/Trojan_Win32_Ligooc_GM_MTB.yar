
rule Trojan_Win32_Ligooc_GM_MTB{
	meta:
		description = "Trojan:Win32/Ligooc.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b da 8a 54 1c ?? 88 54 3c ?? 88 4c 1c } //1
		$a_02_1 = {33 c0 8a 44 3c ?? 81 e1 ?? ?? ?? ?? 03 c1 [0-30] 8a 45 ?? 83 c4 ?? 8a 54 14 ?? 32 c2 88 45 ?? 8b 44 24 [0-20] 89 44 24 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}