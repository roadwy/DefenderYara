
rule Trojan_Win32_Raccoon_CREC_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.CREC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 33 d2 8b 45 08 f7 f1 8b 45 f8 8a 0c 02 8b 55 08 8b 45 fc 03 d7 68 ?? ?? ?? ?? 8a 04 10 32 c1 88 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}