
rule Trojan_Win32_Ekstak_ASDH_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 6a 14 6a 40 ff 15 90 01 02 65 00 8b f0 6a 01 56 ff 15 90 01 02 65 00 53 53 6a 01 56 ff 15 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}