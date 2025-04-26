
rule Trojan_Win32_NSISInject_SMTY_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.SMTY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e1 05 0b c1 0f b6 55 [0-03] 33 c2 8b 4d ?? 88 81 [0-05] 8b 45 [0-03] 83 c0 01 99 b9 0d 00 00 00 f7 f9 89 55 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}