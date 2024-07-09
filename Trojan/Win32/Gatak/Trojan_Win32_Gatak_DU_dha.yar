
rule Trojan_Win32_Gatak_DU_dha{
	meta:
		description = "Trojan:Win32/Gatak.DU!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f8 68 eb 2f 76 e0 e8 ?? ?? ?? ?? 68 5e ce d6 e9 89 45 ?? e8 ?? ?? ?? ?? 68 f2 79 36 18 89 45 ?? e8 ?? ?? ?? ?? 8b 7d ?? 33 f6 89 45 ?? 8a 07 83 c4 0c 46 3c 43 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}