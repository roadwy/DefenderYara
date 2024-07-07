
rule Trojan_Win32_Amadey_ADY_MTB{
	meta:
		description = "Trojan:Win32/Amadey.ADY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 4d ed 0f b6 55 ed f7 da 88 55 ed 0f b6 45 ed f7 d0 88 45 ed 0f b6 4d ed 81 c1 90 01 04 88 4d ed 0f b6 55 ed f7 da 88 55 ed 0f b6 45 ed 83 e8 0d 88 45 ed 8b 4d c8 8a 55 ed 88 54 0d 9c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Amadey_ADY_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.ADY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b1 74 b2 72 68 90 01 04 50 a3 90 01 04 c6 05 90 01 04 56 c6 05 90 01 04 69 88 15 90 01 04 c6 05 90 01 04 50 88 0d 90 01 04 c6 05 90 01 04 00 88 0d 90 01 04 c6 05 90 01 04 75 c6 05 90 01 04 61 c6 05 90 01 04 6c 88 15 90 01 04 c6 05 90 01 04 6f 88 0d 90 01 04 c6 05 90 01 04 65 c6 05 90 01 04 63 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}