
rule Trojan_Win32_NSISInject_FZ_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.FZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 10 8b 55 90 01 01 03 55 90 01 01 0f b6 02 33 c1 8b 4d 90 01 01 03 4d 90 01 01 88 01 8b 55 90 01 01 83 c2 01 89 55 90 01 01 81 7d 90 01 05 7d 90 09 0e 00 8b 45 90 01 01 99 b9 90 01 04 f7 f9 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}