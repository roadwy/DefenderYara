
rule Trojan_Win32_CryptInject_PNK_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 04 01 8b 4d 08 32 04 11 83 3d 60 bd b7 6b 00 88 45 c8 } //1
		$a_01_1 = {8b 4d b4 8b 55 c4 8a 45 c8 88 04 11 81 3d 60 bd b7 6b 92 0f 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}