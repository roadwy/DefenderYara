
rule Trojan_Win32_Copak_CCHS_MTB{
	meta:
		description = "Trojan:Win32/Copak.CCHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 31 19 81 c0 31 ?? ?? ?? ?? 09 ff 81 ef ?? ?? ?? ?? 39 f1 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}