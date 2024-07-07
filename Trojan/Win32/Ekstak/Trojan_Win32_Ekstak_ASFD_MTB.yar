
rule Trojan_Win32_Ekstak_ASFD_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d7 8d 4d fc 8b f0 51 68 00 00 00 02 56 ff 15 90 01 03 00 85 c0 74 90 01 01 8b 45 fc 8d 55 f8 6a 04 52 6a 18 50 ff 15 90 01 03 00 85 c0 74 12 8b 4d fc 51 ff 15 90 01 03 00 85 f6 74 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}