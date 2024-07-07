
rule Trojan_Win32_Amadey_RDU_MTB{
	meta:
		description = "Trojan:Win32/Amadey.RDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 14 08 a1 90 01 04 88 14 08 41 3b 0d 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}