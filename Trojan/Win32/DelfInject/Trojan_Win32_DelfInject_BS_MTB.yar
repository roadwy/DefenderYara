
rule Trojan_Win32_DelfInject_BS_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {e8 88 4d f7 89 55 f8 89 45 fc 8b 45 fc 03 45 f8 } //1
		$a_02_1 = {8a 00 88 45 90 01 01 8b 45 90 01 01 89 45 90 01 01 8a 45 90 01 01 30 45 f7 8b 45 90 01 01 8a 55 f7 88 10 8b e5 5d c3 90 09 06 00 89 45 90 01 01 8b 45 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}