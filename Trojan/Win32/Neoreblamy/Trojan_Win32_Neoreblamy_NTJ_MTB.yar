
rule Trojan_Win32_Neoreblamy_NTJ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NTJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 08 58 6b c0 00 8d 84 05 ?? ?? ff ff 6a 04 59 c1 e1 00 } //1
		$a_01_1 = {eb 07 8b 45 e4 40 89 45 e4 83 7d e4 01 7d 10 8b 45 e4 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}