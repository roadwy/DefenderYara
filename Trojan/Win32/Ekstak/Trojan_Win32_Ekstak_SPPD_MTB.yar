
rule Trojan_Win32_Ekstak_SPPD_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.SPPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 da 0a 00 ae 80 20 73 e7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}