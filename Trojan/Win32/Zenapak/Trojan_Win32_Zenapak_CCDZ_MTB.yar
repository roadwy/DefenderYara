
rule Trojan_Win32_Zenapak_CCDZ_MTB{
	meta:
		description = "Trojan:Win32/Zenapak.CCDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 c7 0f b7 ce 31 d8 8b 9d ?? ?? ?? ?? 31 d9 8b 9d ?? ?? ?? ?? 01 d8 8b 9d ?? ?? ?? ?? 01 d9 81 c2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}