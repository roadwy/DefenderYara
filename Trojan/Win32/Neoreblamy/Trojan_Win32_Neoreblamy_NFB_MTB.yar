
rule Trojan_Win32_Neoreblamy_NFB_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 1b 6a 04 58 6b c0 00 8b 84 05 90 fd ff ff 48 6a 04 59 6b c9 00 89 84 0d 90 fd ff ff 6a 04 58 6b c0 00 } //2
		$a_01_1 = {eb 07 8b 45 e4 40 89 45 e4 83 7d e4 01 7d 0d 8b 45 e4 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}