
rule Trojan_Win32_Zusy_AMAB_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 b4 c1 ea 05 29 f3 29 f7 29 d0 89 c2 8b 45 ac 40 66 89 11 3d } //2
		$a_01_1 = {8b 5d d0 8b 55 e8 01 da 8b 5d e8 89 4d e8 29 d8 89 cb 8b 4d d0 01 d9 8a 1c 02 42 88 5a ff 39 d1 } //2
		$a_80_2 = {54 69 61 6e 71 69 44 72 65 61 6d } //TianqiDream  1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_80_2  & 1)*1) >=5
 
}