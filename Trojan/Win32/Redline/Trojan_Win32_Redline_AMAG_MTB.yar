
rule Trojan_Win32_Redline_AMAG_MTB{
	meta:
		description = "Trojan:Win32/Redline.AMAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 3c ?? 83 c4 ?? 03 c6 0f b6 c0 0f b6 44 04 ?? 30 85 ?? ?? ?? ?? 45 81 fd } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}