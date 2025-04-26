
rule Trojan_Win32_OrcusRat_MBXQ_MTB{
	meta:
		description = "Trojan:Win32/OrcusRat.MBXQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 11 a4 02 42 00 00 08 31 08 a1 ?? ?? ?? 00 08 00 c8 eb 56 00 } //3
		$a_01_1 = {64 1b 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 03 00 00 00 e9 00 00 00 d0 15 40 00 d8 14 40 00 f0 13 40 00 78 00 00 00 80 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}