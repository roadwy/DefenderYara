
rule Trojan_Win32_Zenapak_CCDI_MTB{
	meta:
		description = "Trojan:Win32/Zenapak.CCDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 da 81 c2 ?? ?? ?? ?? 0f b7 12 31 f2 8b b5 ?? ?? ?? ?? 01 ce 89 34 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}