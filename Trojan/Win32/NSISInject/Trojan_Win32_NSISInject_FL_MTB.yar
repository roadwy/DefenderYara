
rule Trojan_Win32_NSISInject_FL_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.FL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 04 24 00 00 00 00 89 44 24 04 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 ff 15 } //10
		$a_03_1 = {88 14 08 8b 45 f8 83 c0 01 89 45 f8 8b 45 f8 3b 45 f0 0f 83 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 45 f4 31 c9 89 04 24 c7 44 24 04 00 00 00 00 ff 15 ?? ?? ?? ?? 83 ec 08 c7 45 fc 00 00 00 00 8b 45 fc 83 c4 34 5d c3 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}