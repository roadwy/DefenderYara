
rule Trojan_Win32_Gepys_MTB{
	meta:
		description = "Trojan:Win32/Gepys!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 da 88 c1 d3 e2 8d 0c 10 89 f8 83 c8 01 03 4d 08 0f af c3 29 c7 8a 11 03 7d 08 ff 4d e4 8a 07 88 17 88 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}