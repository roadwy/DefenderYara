
rule Trojan_Win32_SmokeLoader_RDM_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 f3 31 74 24 10 8b 44 24 10 29 44 24 14 8d 44 24 18 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}