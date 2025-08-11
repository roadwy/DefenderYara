
rule Trojan_Win32_Neoreblamy_NFQ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 40 c1 e0 00 0f b6 84 05 ?? ?? ff ff 0d ef 00 00 00 33 c9 41 c1 e1 00 0f b6 8c 0d ?? ?? ff ff 81 e1 ef 00 00 00 2b c1 33 c9 41 6b c9 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}