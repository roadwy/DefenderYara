
rule Trojan_Win64_BumbleBee_SG_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 07 48 0d 90 01 04 49 90 01 06 49 81 bd 90 01 08 74 90 01 01 49 8b 85 90 01 04 48 90 01 06 48 90 01 06 49 90 01 06 49 90 01 06 41 ba 90 01 04 4d 90 01 06 69 90 01 09 41 8b 88 90 01 04 41 03 ca 90 00 } //1
		$a_00_1 = {72 65 67 74 61 73 6b } //1 regtask
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}