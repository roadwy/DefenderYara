
rule Trojan_Win32_SmokeLoader_FXU_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.FXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 84 30 3b 2d 0b 00 8b 0d ?? ?? ?? ?? 88 04 31 81 3d ?? ?? ?? ?? 92 02 00 00 75 16 68 ?? ?? ?? ?? 53 53 ff 15 ?? ?? ?? ?? 53 53 53 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}