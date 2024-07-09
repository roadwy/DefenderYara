
rule Trojan_Win32_Redline_MKR_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 14 1f 83 e3 ?? 8a 8b ?? ?? ?? ?? 32 ca 0f b6 da 8d 04 19 8b 75 ?? 88 04 37 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 28 1c 37 8b de 43 89 5d ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}