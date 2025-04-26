
rule Trojan_Win32_Copak_KAT_MTB{
	meta:
		description = "Trojan:Win32/Copak.KAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 0b 81 c3 ?? ?? ?? ?? 39 fb 75 ef } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}