
rule Trojan_Win32_NSISInject_AT_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f7 f9 8b 45 e4 0f b6 0c 10 8b 55 dc 03 55 f4 0f b6 02 33 c1 8b 4d dc 03 4d f4 88 01 eb } //1
		$a_03_1 = {83 c4 04 89 45 e0 6a 00 6a 00 8b 4d e8 51 e8 [0-04] 83 c4 0c 6a 40 68 00 30 00 00 8b 55 e0 52 6a 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}