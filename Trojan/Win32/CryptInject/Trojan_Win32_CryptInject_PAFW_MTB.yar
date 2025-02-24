
rule Trojan_Win32_CryptInject_PAFW_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PAFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 1f 41 8b 5d 0c 4f 3b 4d 08 0f } //2
		$a_01_1 = {f7 e1 8b c1 c1 ea 04 8d 14 92 c1 e2 02 2b c2 8b 55 0c 0f b6 04 10 2b c1 03 d8 eb } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}