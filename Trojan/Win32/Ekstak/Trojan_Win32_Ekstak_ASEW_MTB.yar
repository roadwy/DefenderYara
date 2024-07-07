
rule Trojan_Win32_Ekstak_ASEW_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 44 24 08 50 ff 15 90 01 03 00 8d 4c 24 08 51 ff 15 90 01 03 00 8d 54 24 08 52 ff d7 56 8b f8 ff 15 90 01 03 00 50 56 57 ff 15 90 01 03 00 85 c0 74 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}