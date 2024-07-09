
rule Trojan_Win32_Stealer_CM_MTB{
	meta:
		description = "Trojan:Win32/Stealer.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {30 49 5d d3 b2 ?? ?? ?? ?? d2 cc 37 93 } //1
		$a_01_1 = {81 ef 04 00 00 00 33 3c 24 31 3c 24 33 3c 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}