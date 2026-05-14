
rule Trojan_Win32_Neoreblamy_NSK_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {7d 75 83 65 d8 00 eb 07 8b 45 d8 40 89 45 d8 } //1
		$a_01_1 = {7d 45 8b 45 d0 2b 45 e0 8b 55 dc 8b 4d d4 d3 e2 33 c2 99 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}