
rule Trojan_Win32_Neoreblamy_CF_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c8 2b 4d ?? ?? 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 ?? 03 45 ?? 59 59 3b f0 0f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}