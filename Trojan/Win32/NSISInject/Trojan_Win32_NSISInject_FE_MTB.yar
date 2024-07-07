
rule Trojan_Win32_NSISInject_FE_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.FE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 04 68 00 30 00 00 68 80 74 d2 1a 56 ff d7 } //10
		$a_03_1 = {46 3b f3 72 90 01 01 6a 00 57 ff 15 90 01 04 81 c1 09 aa 00 00 b8 c2 b4 00 00 2d 0e 6b 01 00 f7 d1 81 f2 f9 a6 00 00 81 fb a8 4f 00 00 74 90 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}