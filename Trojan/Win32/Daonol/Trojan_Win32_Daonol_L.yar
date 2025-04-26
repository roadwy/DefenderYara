
rule Trojan_Win32_Daonol_L{
	meta:
		description = "Trojan:Win32/Daonol.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 89 10 c6 85 ?? ?? ff ff 39 8d 85 ?? ?? ff ff c7 00 6d 69 64 69 90 09 06 00 8d 85 ?? ?? ff ff } //1
		$a_03_1 = {55 ff 53 04 ff d0 85 c0 0f 84 ?? ?? ?? ?? 56 ff 53 10 97 6a 00 6a 01 50 8b 6b 24 03 6d 3c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}