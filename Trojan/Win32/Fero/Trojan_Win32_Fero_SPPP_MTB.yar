
rule Trojan_Win32_Fero_SPPP_MTB{
	meta:
		description = "Trojan:Win32/Fero.SPPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {54 69 68 45 65 74 68 6f 75 65 6f 77 73 } //2 TihEethoueows
	condition:
		((#a_01_0  & 1)*2) >=2
 
}