
rule Trojan_Win32_Neoreblamy_NST_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 c8 40 89 45 c8 83 7d c8 01 7d 10 8b 45 c8 } //1
		$a_03_1 = {6a 08 58 c1 e0 00 8d 84 05 ?? ?? ff ff 6a 04 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}