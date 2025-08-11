
rule Trojan_Win32_Neoreblamy_NFV_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 98 40 89 45 98 83 7d 98 02 7d 10 8b 45 98 } //1
		$a_03_1 = {6a 04 59 d1 e1 8b 8c 0d ?? ?? ff ff 41 6a 04 5a d1 e2 } //2
		$a_01_2 = {eb 07 83 a5 28 fe ff ff 00 6a 04 58 d1 e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=4
 
}