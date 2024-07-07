
rule Trojan_Win32_VBKrypt_AB_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 55 d8 8b 52 0c 8b 49 0c 8a 14 1a 8b 7d 94 32 14 39 83 c6 01 88 14 01 8b 45 e8 0f 80 90 01 04 3b f0 7e 02 33 f6 8b 45 e4 83 c0 01 0f 80 90 01 04 89 45 e4 e9 90 01 01 ff ff ff 90 00 } //1
		$a_00_1 = {46 75 6e 63 78 63 76 63 78 76 78 63 } //1 Funcxcvcxvxc
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}