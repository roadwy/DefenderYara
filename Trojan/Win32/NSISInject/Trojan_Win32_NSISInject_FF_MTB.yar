
rule Trojan_Win32_NSISInject_FF_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.FF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 04 68 00 30 00 00 68 80 74 d2 1a 56 ff d7 } //10
		$a_03_1 = {46 3b f3 72 ?? 6a 00 57 ff 15 ?? ?? ?? ?? 3d 2f e1 00 00 74 ?? f7 d2 81 c3 13 54 01 00 81 ea a7 27 01 00 c2 72 15 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}