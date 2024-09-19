
rule Trojan_Win32_Injuke_AMAD_MTB{
	meta:
		description = "Trojan:Win32/Injuke.AMAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d0 8b 45 ?? 31 10 83 45 ?? 04 6a 00 e8 ?? ?? ?? ?? 83 c0 04 01 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}