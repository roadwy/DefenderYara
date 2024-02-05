
rule Trojan_Win32_NSISInject_AN_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {0f b6 55 ff 81 f2 fb 00 00 00 88 55 ff 0f b6 45 ff 03 45 f4 88 45 ff 0f b6 4d ff 33 4d f4 88 4d ff 0f b6 55 ff f7 d2 88 55 ff 8b 45 e8 03 45 f4 8a 4d ff 88 08 e9 } //00 00 
	condition:
		any of ($a_*)
 
}