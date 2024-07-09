
rule Trojan_Win32_NSISInject_MBG_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.MBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f be 11 81 f2 ?? ?? ?? ?? 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 0f be 11 83 ea 0e 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 8a 11 80 c2 01 8b 45 f8 03 45 fc 88 10 8b 4d fc 83 c1 01 89 4d fc 8b 55 fc 3b 55 } //1
		$a_01_1 = {89 45 f0 6a 40 68 00 30 00 00 8b 55 f0 52 6a 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}