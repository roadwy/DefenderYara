
rule Trojan_Win32_Clipbanker_AMBE_MTB{
	meta:
		description = "Trojan:Win32/Clipbanker.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 33 ed 55 ff 15 90 01 04 85 c0 74 90 01 01 53 56 57 6a 90 01 01 ff 15 90 01 04 8b d8 53 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}