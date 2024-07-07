
rule Trojan_Win32_Fauppod_CO_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.CO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 89 e5 50 8a 45 0c 8a 4d 08 30 c8 } //2
		$a_01_1 = {0f b6 c0 83 c4 04 5d c3 } //2
		$a_03_2 = {55 89 e5 8a 45 0c 8a 4d 08 30 c8 a2 90 01 04 c7 05 90 01 04 7e 0f 00 00 c7 05 90 01 04 51 e9 ff ff 0f b6 c0 5d c3 90 00 } //4
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*4) >=4
 
}