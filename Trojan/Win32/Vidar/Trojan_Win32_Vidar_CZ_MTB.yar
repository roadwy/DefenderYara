
rule Trojan_Win32_Vidar_CZ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 8b 45 ?? 33 d2 f7 f1 8b 45 ?? 8b 4d ?? 8a 04 02 32 04 31 ff 45 ?? 88 06 39 5d ?? 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}