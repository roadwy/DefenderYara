
rule Trojan_Win32_Neoreblamy_NTO_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NTO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 08 58 c1 e0 02 8d 84 05 ?? ?? ff ff 6a 04 59 } //1
		$a_01_1 = {eb 07 8b 45 94 40 89 45 94 83 7d 94 04 7d 10 8b 45 94 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}