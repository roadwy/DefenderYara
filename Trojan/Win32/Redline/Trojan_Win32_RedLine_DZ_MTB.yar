
rule Trojan_Win32_RedLine_DZ_MTB{
	meta:
		description = "Trojan:Win32/RedLine.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 88 c7 2c 81 6f 13 f8 f3 a6 fa 04 ed 6d 57 40 ed 3e 94 3f 48 85 21 4f a1 3d 45 3c 0a 3f 0e 07 06 38 f0 5b 24 63 6a 57 55 bb c2 27 78 89 cb 7c } //01 00 
		$a_01_1 = {2b f9 ee ff 08 41 72 d0 f9 83 6a 63 a2 f1 cd ae 4e 7b 04 22 4d e3 cc 35 0c 5d 98 cd 8d 48 ea 6f 35 cb ad ce 93 56 96 b2 bf 89 51 d7 2a ef c7 50 7d 5e 06 ba a8 d7 c7 84 54 88 72 de 49 8e 3d 6c } //00 00 
	condition:
		any of ($a_*)
 
}