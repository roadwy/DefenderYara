
rule Trojan_Win32_Neoreblamy_NUL_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NUL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 09 8b 45 d0 83 c0 01 89 45 d0 83 7d d0 01 7d 10 8b 4d d0 } //1
		$a_03_1 = {b8 04 00 00 00 6b c8 00 8b 94 0d ?? ?? ff ff 83 c2 01 b8 04 00 00 00 6b c8 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}