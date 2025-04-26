
rule Trojan_Win32_NSISInject_AE_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b f0 6a 40 68 00 30 00 00 68 [0-04] 57 ff 15 [0-04] 56 6a 01 8b d8 68 b4 12 00 00 53 ff 15 } //1
		$a_03_1 = {8a 04 3b 2c ?? 34 ?? 04 ?? 34 ?? 04 ?? 34 ?? 04 ?? 34 ?? 88 04 3b 47 81 ff [0-04] 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}