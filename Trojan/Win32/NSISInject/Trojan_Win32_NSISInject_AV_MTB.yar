
rule Trojan_Win32_NSISInject_AV_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 99 b9 0c 00 00 00 f7 f9 8b 45 ec 0f b6 0c 10 8b 55 f8 03 55 fc 0f b6 02 33 c1 8b 4d f8 03 4d fc 88 01 eb } //2
		$a_03_1 = {83 c4 04 89 45 f0 6a 00 6a 00 8b 4d f4 51 e8 [0-04] 83 c4 0c 6a 40 68 00 30 00 00 8b 55 f0 52 6a 00 ff 15 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}