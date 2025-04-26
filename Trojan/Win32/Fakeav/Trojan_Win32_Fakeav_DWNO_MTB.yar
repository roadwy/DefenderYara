
rule Trojan_Win32_Fakeav_DWNO_MTB{
	meta:
		description = "Trojan:Win32/Fakeav.DWNO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a d0 c0 c2 04 8a c2 24 0f bb e1 4a 40 00 d7 a2 44 4e 40 00 c0 c2 04 8a c2 24 0f d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}