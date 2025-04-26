
rule Trojan_Win32_Zusy_ABRL_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ABRL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {4a 73 65 69 6f 70 73 67 6f 70 65 67 69 6f 73 6a 69 6f 68 68 } //2 Jseiopsgopegiosjiohh
		$a_01_1 = {4c 6f 70 61 67 69 6f 65 6f 69 67 69 6a 69 65 6a 68 65 73 } //2 Lopagioeoigijiejhes
		$a_01_2 = {66 6f 72 6b 35 2e 64 6c 6c } //2 fork5.dll
		$a_01_3 = {50 6f 61 69 6f 73 6a 76 69 62 69 6e 69 6f 70 71 70 64 6f } //2 Poaiosjvibiniopqpdo
		$a_01_4 = {6f 68 6e 62 69 70 41 6f 6b 76 75 6e 6f 77 70 76 68 76 6f 72 6a } //2 ohnbipAokvunowpvhvorj
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}