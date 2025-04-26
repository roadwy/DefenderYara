
rule Trojan_Win32_Redline_AMAE_MTB{
	meta:
		description = "Trojan:Win32/Redline.AMAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 8d 4c 24 ?? 8a 44 04 ?? 30 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 74 24 ?? 45 81 fd ?? ?? ?? 00 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}