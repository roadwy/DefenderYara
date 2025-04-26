
rule Trojan_Win32_Injector_MPY_MTB{
	meta:
		description = "Trojan:Win32/Injector.MPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 31 00 00 00 00 66 61 31 00 0c 00 } //1
		$a_01_1 = {33 71 b5 86 8e bf c7 50 7e 90 41 8e 94 26 00 83 0f 56 59 2a 3d fb fc fa a0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}