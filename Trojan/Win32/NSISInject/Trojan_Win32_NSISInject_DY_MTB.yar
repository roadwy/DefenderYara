
rule Trojan_Win32_NSISInject_DY_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 8b 4d f4 51 6a 00 ff 15 } //5
		$a_03_1 = {8b 4d f8 03 4d fc 88 01 e9 ?? ?? ?? ?? 6a 00 6a 00 8b 55 f8 52 ff 15 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*1) >=6
 
}