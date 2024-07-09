
rule Trojan_Win32_Scarsi_G_MTB{
	meta:
		description = "Trojan:Win32/Scarsi.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 02 ff 45 ?? 81 7d [0-30] 90 13 [0-30] 83 7d [0-30] 8b 45 [0-40] 8b 45 ?? 8a 80 [0-10] 34 0d 8b 55 ?? 03 55 ?? 88 02 [0-20] 8b 45 ?? 8a 80 ?? ?? ?? ?? 8b 55 ?? 03 55 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}