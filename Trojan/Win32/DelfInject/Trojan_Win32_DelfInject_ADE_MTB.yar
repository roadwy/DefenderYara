
rule Trojan_Win32_DelfInject_ADE_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.ADE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 16 88 c3 32 da c1 e8 08 33 04 9d 40 54 41 00 88 c3 32 de c1 e8 08 33 04 9d 40 54 41 00 c1 ea 10 88 c3 32 da c1 e8 08 33 04 9d 40 54 41 00 88 c3 32 de c1 e8 08 33 04 9d 40 54 41 00 83 c6 04 } //2
		$a_01_1 = {88 c3 32 1e c1 e8 08 46 33 04 9d 40 54 41 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}