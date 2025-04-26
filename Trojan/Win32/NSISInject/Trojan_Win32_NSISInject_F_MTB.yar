
rule Trojan_Win32_NSISInject_F_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 45 dc 00 00 00 00 c7 04 24 00 00 00 00 c7 44 24 04 00 a3 e1 11 c7 44 24 08 00 30 00 00 c7 44 24 0c 04 00 00 00 89 45 d8 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}