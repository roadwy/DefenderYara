
rule Trojan_Win32_Stealerc_AMAG_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.AMAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c6 0f b6 c0 0f b6 44 04 ?? 30 81 ?? ?? ?? ?? 41 89 4c 24 ?? 81 f9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}