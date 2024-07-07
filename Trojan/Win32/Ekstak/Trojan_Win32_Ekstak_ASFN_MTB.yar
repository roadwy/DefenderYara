
rule Trojan_Win32_Ekstak_ASFN_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 d2 0a 00 85 0d 45 b0 90 01 03 00 00 d4 00 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}