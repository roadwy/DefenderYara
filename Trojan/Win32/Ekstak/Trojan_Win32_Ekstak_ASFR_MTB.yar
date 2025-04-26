
rule Trojan_Win32_Ekstak_ASFR_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {51 56 c7 44 24 04 00 00 00 00 ff 15 ?? ?? ?? 00 8b f0 ff 15 ?? ?? ?? 00 85 f6 a3 ?? ?? ?? 00 74 11 8d 44 24 04 50 56 ff 15 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}