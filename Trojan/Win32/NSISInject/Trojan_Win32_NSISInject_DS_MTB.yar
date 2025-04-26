
rule Trojan_Win32_NSISInject_DS_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 f9 0c 13 00 00 74 ?? fe c8 fe c0 fe c8 fe c0 fe c0 fe c0 2c 70 fe c8 04 cd 04 c7 04 a0 34 4b 2c 99 fe c8 fe c0 fe c0 fe c0 88 84 0d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}