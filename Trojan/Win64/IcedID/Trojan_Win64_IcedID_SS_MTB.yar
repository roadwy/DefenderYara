
rule Trojan_Win64_IcedID_SS_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 44 8b 4d 90 01 01 41 f7 f9 44 90 01 06 44 90 01 07 44 90 01 02 2b 15 90 01 04 2b 15 90 01 04 2b 15 90 01 04 03 15 90 01 04 4c 90 01 02 42 90 01 04 41 90 01 02 44 90 01 02 48 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}