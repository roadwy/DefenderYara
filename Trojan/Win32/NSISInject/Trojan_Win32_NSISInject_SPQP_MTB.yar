
rule Trojan_Win32_NSISInject_SPQP_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.SPQP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 37 fe c8 34 17 04 21 34 98 04 55 34 fc 04 15 88 04 37 46 3b f3 72 e7 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}