
rule Trojan_Win32_Farfli_ASDB_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ASDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 01 c7 45 90 01 01 79 6f 75 72 c7 45 90 01 01 46 75 6e 63 c7 45 90 01 01 74 69 6f 6e 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}