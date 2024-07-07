
rule Trojan_Win32_NSISInject_FI_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.FI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 8b 4d f4 51 6a 00 ff 15 } //10
		$a_03_1 = {8b 4d f8 03 4d fc 88 01 8b 55 fc 83 c2 01 89 55 fc 8b 45 fc 3b 45 f4 73 90 01 01 e9 90 01 04 6a 00 8b 4d f8 51 ff 15 90 01 04 33 c0 8b e5 5d c2 10 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}