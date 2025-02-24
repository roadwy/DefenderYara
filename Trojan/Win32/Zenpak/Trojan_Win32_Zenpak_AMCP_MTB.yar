
rule Trojan_Win32_Zenpak_AMCP_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AMCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 56 50 8a 45 0c 8a 4d 08 31 d2 88 d4 [0-32] 01 f2 88 d0 a2 ?? ?? ?? ?? 8a 45 fa a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8a 45 fb a2 [0-1e] 0f b6 c4 83 c4 04 5e 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}