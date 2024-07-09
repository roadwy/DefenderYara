
rule Trojan_Win32_Xpack_GNF_MTB{
	meta:
		description = "Trojan:Win32/Xpack.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c6 53 8b f1 66 83 fa 10 ?? ?? 33 d2 8a 18 8b ca 81 e1 ?? ?? ?? ?? 8a 4c 4c 0c 32 d9 42 88 18 40 4e } //10
		$a_01_1 = {62 73 33 36 30 2e 63 6f 2e 63 63 } //1 bs360.co.cc
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}