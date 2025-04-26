
rule Trojan_Win64_BlackWidow_GB_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 44 0c 20 42 32 04 16 41 88 02 4d 03 d5 44 3b cb 72 cb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}