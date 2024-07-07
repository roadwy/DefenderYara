
rule Trojan_Win32_NSISInject_DT_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.DT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 8b 45 f4 50 6a 00 ff 15 } //1
		$a_01_1 = {8b 4d f8 03 4d fc 0f b6 11 83 ea 4f 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 8a 11 80 ea 01 8b 45 f8 03 45 fc 88 10 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}