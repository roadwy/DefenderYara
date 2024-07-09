
rule Trojan_Win32_Ekstak_KAB_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 96 0a 00 46 59 ba } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}