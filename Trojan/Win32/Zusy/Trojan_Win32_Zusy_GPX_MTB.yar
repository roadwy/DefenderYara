
rule Trojan_Win32_Zusy_GPX_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 62 0a 00 3c 87 da e7 c8 fd } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}