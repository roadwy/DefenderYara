
rule Trojan_Win32_Shelm_E_MTB{
	meta:
		description = "Trojan:Win32/Shelm.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {80 34 18 59 40 8b 8d ?? ?? ff ff 3b c1 } //2
		$a_03_1 = {99 8d 7f 01 b9 ?? ?? ?? ?? f7 f9 8a 47 ?? 8b 8d ?? ?? ?? ?? fe c2 32 c2 34 ?? 88 04 0e 46 81 fe } //2
		$a_03_2 = {99 8d 76 01 b9 ?? ?? ?? ?? f7 f9 8a 44 33 ?? 32 44 24 ?? fe c2 32 c2 88 46 ff 83 ef } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=2
 
}