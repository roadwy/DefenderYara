
rule Trojan_Win32_Injector_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Injector.RPZ!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 31 db 69 93 08 00 44 00 05 84 08 08 42 89 93 08 00 44 00 f7 e2 89 d0 5b c3 } //1
		$a_01_1 = {88 04 32 46 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}