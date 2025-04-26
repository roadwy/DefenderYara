
rule Trojan_Win32_NSISInject_AR_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 c8 f7 e3 d1 ea 83 e2 fc 8d 04 52 f7 d8 8b 14 24 8a 04 07 30 04 0a 41 47 39 ce 75 } //1
		$a_03_1 = {83 c4 04 89 c6 53 53 57 e8 [0-04] 83 c4 0c 6a 40 68 00 30 00 00 56 53 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}