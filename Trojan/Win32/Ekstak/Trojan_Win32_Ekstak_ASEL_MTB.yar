
rule Trojan_Win32_Ekstak_ASEL_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {51 57 ff 15 ?? ?? ?? 00 8b f8 a1 ?? ?? ?? 00 8b c8 48 83 f9 01 a3 ?? ?? ?? 00 73 4f 56 8b 35 ?? ?? ?? 00 68 ?? ?? ?? 00 ff d6 8d 54 24 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}