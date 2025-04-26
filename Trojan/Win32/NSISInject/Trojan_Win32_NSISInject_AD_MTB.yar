
rule Trojan_Win32_NSISInject_AD_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 8b 4d f4 51 6a 00 ff 15 [0-04] 89 45 f8 8b 55 f0 52 6a 01 8b 45 f4 50 8b 4d f8 51 ff 15 } //1
		$a_01_1 = {8b 55 f8 03 55 fc 8a 02 2c 01 8b 4d f8 03 4d fc 88 01 8b 55 fc 83 c2 01 89 55 fc 8b 45 fc 3b 45 f4 73 05 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}