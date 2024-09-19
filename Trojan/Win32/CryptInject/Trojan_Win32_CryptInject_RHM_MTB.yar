
rule Trojan_Win32_CryptInject_RHM_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.RHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {50 45 00 00 4c 01 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 09 00 00 e2 00 00 00 fe f5 01 00 00 00 00 03 19 } //2
		$a_01_1 = {8d 4d f8 89 7d f8 e8 d3 ff ff ff 8a 45 f8 30 04 33 83 7d 08 0f 75 12 } //2
		$a_01_2 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 38 9a 34 02 0f b7 05 3a 9a 34 02 25 ff 7f 00 00 c3 } //2
		$a_00_3 = {52 00 65 00 66 00 65 00 6e 00 67 00 65 00 } //1 Refenge
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_00_3  & 1)*1) >=7
 
}