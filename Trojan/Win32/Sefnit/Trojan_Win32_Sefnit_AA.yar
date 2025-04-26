
rule Trojan_Win32_Sefnit_AA{
	meta:
		description = "Trojan:Win32/Sefnit.AA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 45 fc 31 4d fc 83 (3d ?? ?? ??|?? ?? 7d ??) ?? 90 17 03 02 01 01 0f 85 74 75 } //2
		$a_03_1 = {66 83 7e 08 3a 0f 85 ?? ?? ?? ?? [0-08] 66 83 7e 0a 2f } //1
		$a_03_2 = {66 83 78 08 3a 0f 85 ?? ?? ?? ?? [0-08] 66 83 78 0a 2f } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}