
rule Trojan_Win32_ThemidaPacked_D_MTB{
	meta:
		description = "Trojan:Win32/ThemidaPacked.D!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 47 29 a9 bf 52 ae 03 c0 81 9e 4f 43 3e 93 d3 34 2e 04 7a e4 56 22 87 4b 03 00 44 97 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}