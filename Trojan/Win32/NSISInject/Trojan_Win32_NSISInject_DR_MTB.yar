
rule Trojan_Win32_NSISInject_DR_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.DR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 f9 c2 13 00 00 74 ?? fe c0 fe c8 fe c0 2c 16 04 06 34 ff fe c0 fe c0 04 80 2c a6 34 67 2c c6 04 78 fe c8 34 e7 88 84 0d ?? ?? ?? ?? 83 c1 01 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}