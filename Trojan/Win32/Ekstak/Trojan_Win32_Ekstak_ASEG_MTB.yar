
rule Trojan_Win32_Ekstak_ASEG_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 08 56 57 ff 15 90 01 02 4b 00 68 90 01 02 4b 00 6a 01 6a 00 8b f8 ff 15 90 01 02 4b 00 8b f0 8d 45 fc 50 57 ff 15 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}