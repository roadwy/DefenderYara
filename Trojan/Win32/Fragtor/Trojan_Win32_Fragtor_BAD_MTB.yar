
rule Trojan_Win32_Fragtor_BAD_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b6 d2 89 55 d8 0f b7 51 0d 0f b6 49 0f c1 e1 10 09 d1 8b 55 dc 89 4d d4 8b 4d e0 8d 3c 0a eb } //2
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_2 = {6e 65 74 73 76 63 73 } //1 netsvcs
		$a_01_3 = {57 61 6b 65 42 79 41 64 64 72 65 73 73 41 6c 6c } //1 WakeByAddressAll
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}