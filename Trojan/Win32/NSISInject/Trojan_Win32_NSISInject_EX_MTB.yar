
rule Trojan_Win32_NSISInject_EX_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.EX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 8b f8 6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 56 ff 15 } //10
		$a_03_1 = {88 04 33 46 81 fe ?? ?? ?? ?? 72 ?? 6a 00 53 ff 15 ?? ?? ?? ?? 5f 5e 33 c0 5b 5d c2 10 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}