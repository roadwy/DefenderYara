
rule Trojan_Win32_Ekstak_ASEX_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 ff d6 8b 0d d8 ?? ?? 00 68 5c e0 4b 00 51 a3 c4 ?? ?? 00 ff d6 8b 15 d8 ?? ?? 00 68 48 e0 4b 00 52 a3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}