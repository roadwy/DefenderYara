
rule Trojan_Win32_Neoreblamy_NJK_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 fc 40 89 45 fc 83 7d fc 01 7d 0d 8b 45 fc } //1
		$a_03_1 = {8d 45 94 50 33 d2 42 33 c9 e8 ?? ?? ff ff 59 59 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}