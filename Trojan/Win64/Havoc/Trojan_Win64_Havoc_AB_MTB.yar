
rule Trojan_Win64_Havoc_AB_MTB{
	meta:
		description = "Trojan:Win64/Havoc.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b ca 2b 08 01 0b 48 8b 05 90 01 04 8b 88 90 01 04 8b 05 90 01 04 03 ca 05 90 01 04 41 8b d0 03 c8 c1 ea 08 89 0d 90 01 04 48 63 4b 90 01 01 48 8b 83 90 01 04 88 14 01 ff 43 90 01 01 48 8b 05 90 01 04 8b 08 31 4b 90 01 01 48 8b 0d 90 01 04 8b 41 28 2d 90 01 04 01 81 90 01 04 48 8b 05 90 01 04 48 63 53 90 01 01 48 8b 88 90 01 04 44 88 04 0a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}