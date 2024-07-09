
rule Trojan_Win32_Clipbanker_AMBE_MTB{
	meta:
		description = "Trojan:Win32/Clipbanker.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 33 ed 55 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 53 56 57 6a ?? ff 15 ?? ?? ?? ?? 8b d8 53 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}