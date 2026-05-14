
rule Trojan_Win32_Neoreblamy_NUG_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NUG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 c4 40 89 45 c4 83 7d c4 01 7d 10 8b 45 c4 } //2
		$a_03_1 = {58 6b c0 00 8b 84 05 ?? ?? ff ff 40 6a 04 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}