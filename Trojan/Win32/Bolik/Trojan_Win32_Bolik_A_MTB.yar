
rule Trojan_Win32_Bolik_A_MTB{
	meta:
		description = "Trojan:Win32/Bolik.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {ff 36 8b 14 24 83 c4 04 31 ca 01 c2 81 ea ?? ?? ?? ?? 31 c2 c1 ca 06 29 c2 c1 c2 16 89 16 83 c6 04 83 e9 04 83 f9 00 77 } //2
		$a_02_1 = {8b 1e c1 cb 08 01 cb 01 cb 81 eb ?? ?? ?? ?? 01 fb 29 cb 81 e9 04 00 00 00 29 fb 89 1e 81 c6 04 00 00 00 81 f9 00 00 00 00 77 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}