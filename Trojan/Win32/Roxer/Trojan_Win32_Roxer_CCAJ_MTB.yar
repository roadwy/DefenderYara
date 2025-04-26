
rule Trojan_Win32_Roxer_CCAJ_MTB{
	meta:
		description = "Trojan:Win32/Roxer.CCAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e6 c1 ea ?? 8d 04 92 8b d6 2b d0 8a 04 95 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 3b f1 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}