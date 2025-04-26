
rule Trojan_Win32_RedLine_RDED_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e8 18 43 33 c6 69 c8 91 e9 d1 5b 33 e9 8b 4c 24 20 3b df } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}