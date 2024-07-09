
rule Trojan_Win32_NSISInject_EG_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 8b 45 f0 50 6a 00 ff 15 } //5
		$a_03_1 = {6a 00 6a 00 8b 55 f8 52 ff 15 ?? ?? ?? ?? 33 c0 8b e5 5d c3 90 09 07 00 88 01 e9 ?? ?? ff ff } //1
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*1) >=6
 
}