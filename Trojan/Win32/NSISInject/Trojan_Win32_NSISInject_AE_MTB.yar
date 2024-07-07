
rule Trojan_Win32_NSISInject_AE_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b f0 6a 40 68 00 30 00 00 68 90 02 04 57 ff 15 90 02 04 56 6a 01 8b d8 68 b4 12 00 00 53 ff 15 90 00 } //1
		$a_03_1 = {8a 04 3b 2c 90 01 01 34 90 01 01 04 90 01 01 34 90 01 01 04 90 01 01 34 90 01 01 04 90 01 01 34 90 01 01 88 04 3b 47 81 ff 90 02 04 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}