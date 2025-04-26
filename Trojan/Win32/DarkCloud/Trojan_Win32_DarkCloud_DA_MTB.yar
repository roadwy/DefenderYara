
rule Trojan_Win32_DarkCloud_DA_MTB{
	meta:
		description = "Trojan:Win32/DarkCloud.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 04 ab 91 e9 d1 5b 89 c1 c1 e9 18 31 c1 69 c1 91 e9 d1 5b 69 f6 91 e9 d1 5b 31 c6 45 39 ef } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}