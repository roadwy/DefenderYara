
rule Trojan_Win32_Ekstak_ASEU_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 54 24 10 8b d8 52 55 ff 15 ?? ?? ?? 00 68 ?? ?? ?? 00 53 8b e8 ff 15 ?? ?? ?? 00 3b ef 89 86 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}