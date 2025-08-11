
rule Trojan_Win32_Cerbu_MBY_MTB{
	meta:
		description = "Trojan:Win32/Cerbu.MBY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c2 8b ce 81 fa ?? ?? ?? 00 0f 43 c8 4e 8a 01 88 04 1a 42 8b 44 24 0c 81 fa ?? ?? ?? 00 72 e0 } //2
		$a_03_1 = {8d 0c 1a 8d 42 01 42 30 01 81 fa ?? ?? ?? 00 72 ef } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}