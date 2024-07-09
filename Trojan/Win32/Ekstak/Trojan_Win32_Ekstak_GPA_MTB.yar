
rule Trojan_Win32_Ekstak_GPA_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ec 75 67 00 0e da 63 00 00 be ?? ?? ?? ?? 14 99 d1 93 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}