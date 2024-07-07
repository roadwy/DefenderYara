
rule Trojan_Win32_NSISInject_EF_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 8b f0 56 6a 00 ff 15 } //5
		$a_03_1 = {88 04 39 41 3b ce 72 90 01 01 6a 00 6a 00 57 ff 15 90 01 04 5f 5e 33 c0 5b 8b e5 5d c3 90 00 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*1) >=6
 
}