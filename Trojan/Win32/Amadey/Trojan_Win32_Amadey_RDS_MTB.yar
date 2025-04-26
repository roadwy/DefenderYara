
rule Trojan_Win32_Amadey_RDS_MTB{
	meta:
		description = "Trojan:Win32/Amadey.RDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 04 8d 47 34 50 8b 83 a4 00 00 00 83 c0 08 50 ff b5 a0 fe ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}