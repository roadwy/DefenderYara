
rule Trojan_Win32_NSISInject_ED_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 50 6a 00 ff 15 } //5
		$a_03_1 = {88 01 41 4e 75 ?? 6a 00 6a 00 57 ff 15 ?? ?? ?? ?? 81 fb d9 58 00 00 74 0d c2 55 d0 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*1) >=6
 
}