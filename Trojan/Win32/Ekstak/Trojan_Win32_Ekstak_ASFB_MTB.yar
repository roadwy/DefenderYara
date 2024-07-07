
rule Trojan_Win32_Ekstak_ASFB_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 55 ff 15 90 01 03 00 68 90 01 03 00 57 8b e8 ff d3 68 90 01 03 00 57 89 46 0c ff d3 68 90 01 03 00 57 89 46 10 ff d3 8b 4e 04 89 46 14 85 c9 90 00 } //5
		$a_03_1 = {ff d3 8b f0 8d 44 24 10 50 57 ff 15 90 01 03 00 85 f6 8b e8 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}