
rule Trojan_Win32_VBInject_CB_MTB{
	meta:
		description = "Trojan:Win32/VBInject.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {66 8b cf 66 83 c1 06 66 0f b6 04 02 66 99 0f 80 90 01 04 66 f7 f9 66 8b ca 8b 13 8b 42 0c 8b 95 90 01 04 66 0f b6 04 10 33 c8 ff 15 90 01 04 8b 0b 8b 51 0c 88 04 32 b8 01 00 00 00 66 03 c7 bf 02 00 00 00 0f 80 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_VBInject_CB_MTB_2{
	meta:
		description = "Trojan:Win32/VBInject.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {66 33 c0 8a c1 8b 4d 90 01 01 66 89 04 79 8b 45 90 01 01 8b 00 8b 58 90 01 01 8b 48 90 01 01 2b cb 8d 04 11 8b 4d 90 01 01 66 8b 1c 79 66 03 1c 71 66 83 e3 0f 79 90 01 01 66 4b 66 83 cb f0 66 43 0f bf db 8a 0c 59 30 08 03 95 90 01 04 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}