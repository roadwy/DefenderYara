
rule Trojan_Win32_NSISInject_BO_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 42 01 99 f7 ff 0f b6 41 fe c0 c8 03 32 82 [0-04] 88 41 fe 8d 42 01 99 f7 ff 83 ee 01 75 } //4
		$a_01_1 = {6a 40 68 00 10 00 00 68 2b 16 00 00 8b f0 6a 00 89 75 fc ff 15 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}