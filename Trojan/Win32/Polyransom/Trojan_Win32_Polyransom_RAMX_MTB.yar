
rule Trojan_Win32_Polyransom_RAMX_MTB{
	meta:
		description = "Trojan:Win32/Polyransom.RAMX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 90 88 07 90 42 46 47 90 49 } //2
		$a_01_1 = {32 c2 90 88 07 46 47 49 83 f9 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}