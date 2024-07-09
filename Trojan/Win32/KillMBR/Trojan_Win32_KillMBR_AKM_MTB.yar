
rule Trojan_Win32_KillMBR_AKM_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.AKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 00 ca 9a 3b 8b c7 8b bc 24 ?? ?? ?? ?? f7 e1 ba 00 ca 9a 3b 8b c8 8b 44 24 ?? f7 e2 03 ca 03 f0 8b 84 24 ?? ?? ?? ?? 13 c1 89 b4 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}