
rule Trojan_Win32_Injector_ZA_MTB{
	meta:
		description = "Trojan:Win32/Injector.ZA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {84 c9 83 c2 04 84 c9 83 c7 04 } //1
		$a_01_1 = {66 85 db 31 f5 84 c0 31 2c 10 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}