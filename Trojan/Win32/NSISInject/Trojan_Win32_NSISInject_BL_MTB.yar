
rule Trojan_Win32_NSISInject_BL_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 99 b9 0c 00 00 00 f7 f9 8b 45 e8 0f b6 0c 10 8b 55 d4 03 55 fc 0f b6 02 33 c1 8b 4d d4 03 4d fc 88 01 eb } //02 00 
		$a_01_1 = {89 45 f8 6a 40 68 00 10 00 00 68 6e 16 00 00 6a 00 ff 55 } //00 00 
	condition:
		any of ($a_*)
 
}