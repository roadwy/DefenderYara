
rule Trojan_Win32_NSISInject_DX_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 8b 4d f4 51 6a 00 ff 15 } //5
		$a_03_1 = {8b 4d f8 03 4d fc 88 01 e9 90 01 02 ff ff 8b 45 f8 ff e0 90 00 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*1) >=6
 
}