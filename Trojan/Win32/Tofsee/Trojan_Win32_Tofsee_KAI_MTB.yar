
rule Trojan_Win32_Tofsee_KAI_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.KAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 c0 2b 03 f7 d8 83 c3 ?? f7 d8 83 e8 ?? 83 c0 ?? 83 e8 ?? 29 f0 29 f6 29 c6 f7 de c7 41 ?? ?? ?? ?? ?? 31 01 83 c1 ?? 83 ef ?? 85 ff 75 d1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}