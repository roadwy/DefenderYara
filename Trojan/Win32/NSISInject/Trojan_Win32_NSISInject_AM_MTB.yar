
rule Trojan_Win32_NSISInject_AM_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 37 34 3e 04 6d 34 be fe c0 34 a9 04 37 88 04 37 46 3b f3 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}