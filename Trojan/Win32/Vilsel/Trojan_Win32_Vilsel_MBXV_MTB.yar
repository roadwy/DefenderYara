
rule Trojan_Win32_Vilsel_MBXV_MTB{
	meta:
		description = "Trojan:Win32/Vilsel.MBXV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 6e 08 8b 7e 20 8b 36 38 47 18 75 } //3
		$a_01_1 = {20 24 40 00 a8 12 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 00 00 00 00 e9 00 00 00 20 11 40 00 20 11 40 00 e4 10 40 00 78 00 00 00 80 00 00 00 83 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}