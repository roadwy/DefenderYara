
rule Trojan_Win32_NSISInject_BQ_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 0f c0 c8 03 32 82 90 02 04 88 04 0f 8d 42 01 6a 0c 99 5e f7 fe 41 3b cb 72 90 00 } //4
		$a_01_1 = {55 8b ec 6a 40 68 00 30 00 00 ff 75 08 6a 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}