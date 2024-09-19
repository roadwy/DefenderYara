
rule Trojan_Win32_Vilsel_MBXQ_MTB{
	meta:
		description = "Trojan:Win32/Vilsel.MBXQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {34 73 40 00 00 f8 32 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 6c 6a 40 00 6c 6a 40 00 5c 11 40 00 78 00 00 00 80 00 00 00 92 00 00 00 93 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}