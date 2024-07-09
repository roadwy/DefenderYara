
rule Trojan_Win32_Uztuby_KAA_MTB{
	meta:
		description = "Trojan:Win32/Uztuby.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f2 02 89 d0 01 c2 42 89 35 ?? ?? ?? ?? 42 b8 ?? ?? ?? ?? 89 d0 31 1d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}