
rule Trojan_Win32_NSISInject_EL_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.EL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 50 53 ff 15 } //5
		$a_03_1 = {8b 0c 24 80 ?? ?? ?? 40 39 c6 75 ?? 8b 04 24 ff e0 83 c4 0c 5e 5f 5b c3 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*1) >=6
 
}