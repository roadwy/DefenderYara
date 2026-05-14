
rule Trojan_Win32_Polyransom_RMX_MTB{
	meta:
		description = "Trojan:Win32/Polyransom.RMX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 90 47 90 49 83 f9 00 90 0f 85 } //2
		$a_01_1 = {8a 06 90 32 c2 90 88 07 46 90 47 49 } //2
		$a_01_2 = {32 c2 88 07 90 46 47 49 90 83 f9 00 90 } //2
		$a_01_3 = {88 07 90 42 46 47 90 49 83 f9 00 90 e9 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=2
 
}