
rule Trojan_Win32_NSISInject_DV_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {89 45 f4 6a 40 68 00 30 00 00 8b 4d f4 51 6a 00 ff 15 } //5
		$a_01_1 = {8a 02 04 01 8b 4d f8 03 4d fc 88 01 8b 55 f8 03 55 fc 0f b6 02 83 f0 0d 8b 4d f8 03 4d fc 88 01 } //1
		$a_01_2 = {0f b6 02 83 f0 69 8b 4d f8 03 4d fc 88 01 8b 55 f8 03 55 fc 0f b6 02 83 f0 64 8b 4d f8 03 4d fc 88 01 } //1
		$a_01_3 = {8a 02 04 01 8b 4d f8 03 4d fc 88 01 8b 55 f8 03 55 fc 0f b6 02 83 c0 0e 8b 4d f8 03 4d fc 88 01 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}