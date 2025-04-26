
rule Trojan_Win32_Injector_DFE_MTB{
	meta:
		description = "Trojan:Win32/Injector.DFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 3b 87 aa 7f 2c f7 0f 87 4c 7f 17 f7 79 87 e3 7f 96 f7 86 87 98 7f de f7 91 87 6c 7f e2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}