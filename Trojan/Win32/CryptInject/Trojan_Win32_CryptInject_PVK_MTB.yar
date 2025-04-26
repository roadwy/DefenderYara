
rule Trojan_Win32_CryptInject_PVK_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PVK!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 54 30 01 8b 75 10 c0 e9 04 c0 e2 04 0a ca 88 4d ff eb } //2
		$a_01_1 = {8a 55 ff 47 d0 e2 83 ff 08 89 7d ec 88 55 ff 0f 8c } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}