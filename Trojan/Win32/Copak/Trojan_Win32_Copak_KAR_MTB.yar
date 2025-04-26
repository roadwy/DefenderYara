
rule Trojan_Win32_Copak_KAR_MTB{
	meta:
		description = "Trojan:Win32/Copak.KAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 13 89 ce 29 cf 81 e2 ?? ?? ?? ?? 29 f9 89 fe 46 31 10 29 cf 01 f6 40 47 29 f9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}