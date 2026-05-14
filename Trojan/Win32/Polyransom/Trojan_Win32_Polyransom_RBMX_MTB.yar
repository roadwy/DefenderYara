
rule Trojan_Win32_Polyransom_RBMX_MTB{
	meta:
		description = "Trojan:Win32/Polyransom.RBMX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 06 90 32 c2 88 07 42 46 90 47 90 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}