
rule Trojan_Win32_Redline_AMAS_MTB{
	meta:
		description = "Trojan:Win32/Redline.AMAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {46 56 89 74 24 ?? e8 ?? ?? ?? ?? 8d 4c 24 ?? ff 30 e8 ?? ?? ?? ?? 8d 4c 24 ?? 8a 00 30 07 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}