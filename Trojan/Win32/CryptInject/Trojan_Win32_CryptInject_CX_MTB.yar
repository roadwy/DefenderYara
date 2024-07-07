
rule Trojan_Win32_CryptInject_CX_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 16 30 04 13 83 c2 01 39 d5 77 f2 } //2
		$a_01_1 = {0f b6 4c 03 01 30 4c 14 20 8d 50 02 39 d7 76 09 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}