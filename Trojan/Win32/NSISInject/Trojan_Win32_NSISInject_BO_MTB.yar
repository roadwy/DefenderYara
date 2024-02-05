
rule Trojan_Win32_NSISInject_BO_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {8d 42 01 99 f7 ff 0f b6 41 fe c0 c8 03 32 82 90 02 04 88 41 fe 8d 42 01 99 f7 ff 83 ee 01 75 90 00 } //01 00 
		$a_01_1 = {6a 40 68 00 10 00 00 68 2b 16 00 00 8b f0 6a 00 89 75 fc ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}