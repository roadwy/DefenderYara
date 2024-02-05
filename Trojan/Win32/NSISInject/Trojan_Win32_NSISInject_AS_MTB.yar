
rule Trojan_Win32_NSISInject_AS_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {0f b6 4d ff 81 f1 b9 00 00 00 88 4d ff 0f b6 55 ff 2b 55 f8 88 55 ff 0f b6 45 ff f7 d8 88 45 ff 8b 4d e8 03 4d f8 8a 55 ff 88 11 e9 } //00 00 
	condition:
		any of ($a_*)
 
}