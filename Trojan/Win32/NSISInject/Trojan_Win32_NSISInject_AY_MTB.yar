
rule Trojan_Win32_NSISInject_AY_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c1 99 6a 0c 5e f7 fe 8a 82 90 02 04 30 04 0b 41 3b cf 72 90 00 } //2
		$a_03_1 = {83 c4 24 6a 40 68 00 30 00 00 57 53 ff 15 90 02 04 56 6a 01 8b d8 57 53 e8 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}