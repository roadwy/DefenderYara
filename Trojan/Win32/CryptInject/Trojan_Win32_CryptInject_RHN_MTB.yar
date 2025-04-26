
rule Trojan_Win32_CryptInject_RHN_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.RHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {50 45 00 00 4c 01 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0a 00 00 06 02 00 00 8c 4d 00 00 00 00 00 6a 6c } //2
		$a_01_1 = {b8 6b 00 00 00 ba 72 00 00 00 66 a3 08 3e 8e 00 66 89 15 0c 3e 8e 00 b9 6e 00 00 00 ba 65 00 00 00 33 c0 } //2
		$a_01_2 = {a8 25 00 00 07 00 18 18 00 00 01 00 20 00 88 09 00 00 08 00 } //2
		$a_00_3 = {53 00 68 00 65 00 61 00 74 00 68 00 6f 00 6c 00 65 00 } //1 Sheathole
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_00_3  & 1)*1) >=7
 
}