
rule Trojan_Win32_Copak_KAS_MTB{
	meta:
		description = "Trojan:Win32/Copak.KAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4f 09 f7 31 03 81 ef ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 29 f6 43 29 fe 81 c7 01 00 00 00 39 cb 75 ce } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}