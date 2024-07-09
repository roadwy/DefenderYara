
rule Trojan_Win32_Zegost_RB_MTB{
	meta:
		description = "Trojan:Win32/Zegost.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 6a 40 68 00 30 00 00 68 5c dd 04 00 8b f1 6a 00 ff 15 ?? ?? ?? ?? 85 c0 75 02 5e c3 57 6a 00 6a 00 50 b9 57 37 01 00 81 c6 74 dd 04 00 8b f8 50 6a 00 6a 00 f3 a5 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}