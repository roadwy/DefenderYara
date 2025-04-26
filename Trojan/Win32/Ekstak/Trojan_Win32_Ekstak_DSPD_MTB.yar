
rule Trojan_Win32_Ekstak_DSPD_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.DSPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 06 39 5e 00 ab 90 5a 00 00 da 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}