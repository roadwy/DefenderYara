
rule Trojan_Win32_Ekstak_ASEJ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 44 24 04 bb 01 00 00 00 50 53 6a 00 68 90 01 03 00 68 00 00 00 80 c7 44 24 18 00 00 00 00 ff 15 90 01 03 00 85 c0 a3 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}