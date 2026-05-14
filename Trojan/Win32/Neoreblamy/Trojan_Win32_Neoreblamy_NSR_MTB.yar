
rule Trojan_Win32_Neoreblamy_NSR_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NSR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 58 c1 e0 00 8d 84 05 ?? ?? ff ff 6a 04 59 6b c9 00 } //1
		$a_01_1 = {eb 07 8b 45 e4 40 89 45 e4 83 7d e4 01 7d 16 8b } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}