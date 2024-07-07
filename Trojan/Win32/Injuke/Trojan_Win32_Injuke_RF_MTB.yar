
rule Trojan_Win32_Injuke_RF_MTB{
	meta:
		description = "Trojan:Win32/Injuke.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe ff ff 8a 84 1d 90 01 01 fe ff ff 88 84 3d 90 01 01 fe ff ff 88 8c 1d 90 01 01 fe ff ff 0f b6 84 3d 90 01 01 fe ff ff 03 c2 0f b6 c0 8a 84 05 90 01 01 fe ff ff 32 86 90 01 04 88 86 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}