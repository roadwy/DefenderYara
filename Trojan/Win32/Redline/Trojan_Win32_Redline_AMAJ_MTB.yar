
rule Trojan_Win32_Redline_AMAJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.AMAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 06 6a 03 8b 0c 81 8a 04 3b 30 04 11 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}