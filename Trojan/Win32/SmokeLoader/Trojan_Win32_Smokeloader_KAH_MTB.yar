
rule Trojan_Win32_Smokeloader_KAH_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.KAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 06 75 04 a9 ?? ?? ?? ?? 30 75 ?? 74 03 f7 be ?? ?? ?? ?? 84 29 c0 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}