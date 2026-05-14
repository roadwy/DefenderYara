
rule Trojan_Win32_Neoreblamy_NSJ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NSJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {d3 e0 8b 55 d0 8b 4d e4 d3 fa 23 c2 99 } //1
		$a_01_1 = {7d 5f 83 65 e4 00 eb 07 8b 45 e4 40 89 45 e4 81 7d e4 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}