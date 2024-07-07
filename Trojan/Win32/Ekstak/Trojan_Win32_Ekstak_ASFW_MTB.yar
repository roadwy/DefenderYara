
rule Trojan_Win32_Ekstak_ASFW_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {51 53 56 57 ff 15 90 01 08 00 8b f0 e8 90 01 03 ff 83 c4 04 8d 44 24 0c 50 56 ff 15 90 01 03 00 8b f8 ff 15 90 01 03 00 8b d8 8b f3 81 e6 ff 00 00 00 85 ff 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}