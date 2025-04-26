
rule Trojan_Win32_NSISInject_AO_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 99 b9 0c 00 00 00 f7 f9 8b 45 ec 0f b6 0c 10 8b 55 e0 03 55 f8 0f b6 02 33 c1 8b 4d e0 03 4d f8 88 01 eb } //1
		$a_03_1 = {83 c4 0c 6a 40 68 00 30 00 00 8b 45 e4 50 6a 00 ff 15 [0-04] 89 45 e0 8b 4d f0 51 6a 01 8b 55 e4 52 8b 45 e0 50 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}