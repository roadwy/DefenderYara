
rule Trojan_Win32_NSISInject_DZ_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 8b 55 f4 52 6a 00 ff 15 } //5
		$a_03_1 = {8b 55 f8 03 55 fc 88 0a e9 ?? ?? ?? ?? 6a 00 6a 00 8b 45 f8 50 ff 15 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*1) >=6
 
}