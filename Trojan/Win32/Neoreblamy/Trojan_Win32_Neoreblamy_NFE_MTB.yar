
rule Trojan_Win32_Neoreblamy_NFE_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 e8 40 89 45 e8 83 7d e8 01 7d 10 8b 45 e8 } //2
		$a_01_1 = {eb 08 8b 45 d8 40 40 89 45 d8 83 7d d8 0c } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}