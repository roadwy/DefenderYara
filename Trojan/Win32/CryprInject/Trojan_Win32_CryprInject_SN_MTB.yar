
rule Trojan_Win32_CryprInject_SN_MTB{
	meta:
		description = "Trojan:Win32/CryprInject.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {8d 44 24 24 50 c6 44 24 2b 6e c6 44 24 2f 32 c6 44 24 22 6f c6 44 24 1c 75 c6 44 24 19 69 ff 15 90 01 04 0f bf 0d 90 01 04 3b 0d 90 01 04 7f 07 c6 05 90 01 04 d9 8b 1d 90 01 04 8d 4c 24 14 51 50 ff d3 8b f8 b8 90 01 02 00 00 eb 90 00 } //2
		$a_02_1 = {c6 44 24 2a 33 c6 44 24 24 6b c6 44 24 2c 00 c6 44 24 14 56 c6 44 24 17 74 c6 44 24 1d 6c c6 44 24 25 65 c7 44 24 10 90 01 04 c6 44 24 29 6c b9 4a 01 00 00 39 05 90 01 04 75 0b 8b d1 66 39 15 90 01 04 74 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}