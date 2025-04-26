
rule Trojan_Win32_Amadey_CAQQ_MTB{
	meta:
		description = "Trojan:Win32/Amadey.CAQQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 7c 24 10 8b 44 24 14 31 44 24 10 8b 44 24 10 29 44 24 1c 8b 44 24 28 29 44 24 18 ff 4c 24 20 0f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}