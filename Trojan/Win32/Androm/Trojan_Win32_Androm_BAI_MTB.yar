
rule Trojan_Win32_Androm_BAI_MTB{
	meta:
		description = "Trojan:Win32/Androm.BAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 ff 01 1e b8 ?? ?? ?? ?? 03 45 ?? 03 c3 03 c7 89 45 ?? c7 45 ?? 39 19 00 00 6a 00 e8 } //2
		$a_03_1 = {5a 2b d0 31 16 83 c3 04 83 c6 04 3b 5d ?? 72 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}