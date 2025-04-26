
rule Trojan_Win32_NSISInject_AU_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 c8 89 45 c4 8b 45 dc b9 0c 00 00 00 99 f7 f9 8b 45 c4 0f b6 34 10 8b 45 e0 8b 4d dc 0f b6 14 08 31 f2 88 14 08 8b 45 dc 83 c0 01 89 45 dc e9 } //1
		$a_01_1 = {8b 45 d8 31 c9 c7 04 24 00 00 00 00 89 44 24 04 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}