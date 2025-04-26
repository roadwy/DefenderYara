
rule Trojan_Win32_NSISInject_BP_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 0e c0 c8 03 32 82 [0-04] 88 04 0e 8d 42 01 99 c7 45 fc 0c 00 00 00 f7 7d fc 41 81 f9 d9 15 00 00 7c } //4
		$a_01_1 = {6a 40 68 00 10 00 00 68 d9 15 00 00 56 89 45 f8 ff 15 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}