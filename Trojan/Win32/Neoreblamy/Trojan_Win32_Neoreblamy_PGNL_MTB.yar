
rule Trojan_Win32_Neoreblamy_PGNL_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.PGNL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 85 48 ff ff ff 40 89 85 48 ff ff ff 83 bd 48 ff ff ff ?? 7d ?? 8b 85 48 ff ff ff c7 84 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}