
rule Trojan_Win32_LotusBlossom_ARAX_MTB{
	meta:
		description = "Trojan:Win32/LotusBlossom.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 15 24 a3 00 10 25 7f 00 00 80 79 05 48 83 c8 80 40 } //2
		$a_01_1 = {30 84 3d 68 fa ff ff 47 3b fe 72 e2 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}