
rule Trojan_Win32_BlackMoon_ABMN_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.ABMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 40 00 00 00 68 00 10 00 00 68 64 00 00 00 68 00 00 00 00 ff 15 ?? ?? ?? ?? ?? ?? ?? ?? 39 65 ec 74 0d 68 06 00 00 00 e8 ?? ?? ?? ?? 83 c4 04 89 45 f8 89 65 ec 68 40 00 00 00 68 00 10 00 00 68 64 00 00 00 68 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}