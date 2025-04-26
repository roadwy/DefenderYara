
rule Trojan_Win32_Ekstak_GPX_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 48 0a 00 8d 50 e6 0b } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}