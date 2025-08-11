
rule Trojan_Win32_Crypt_SX_MTB{
	meta:
		description = "Trojan:Win32/Crypt.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 ff 89 45 f8 c1 e0 04 8b cf 2b d8 89 7d fc 89 5d 08 39 4d f8 76 4c } //3
		$a_01_1 = {0f b7 01 83 f8 41 72 08 83 f8 5a 77 03 83 c0 20 66 89 04 0e 83 e9 02 4a 75 e6 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}