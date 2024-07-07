
rule Trojan_Win32_NSISInject_DW_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 8b d8 53 6a 00 ff d7 } //5
		$a_01_1 = {8a 04 39 34 65 fe c8 34 49 fe c8 34 a1 04 10 88 04 39 41 3b cb 72 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}