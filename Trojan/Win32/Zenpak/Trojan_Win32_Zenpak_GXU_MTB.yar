
rule Trojan_Win32_Zenpak_GXU_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c2 8d 05 ?? ?? ?? ?? 31 28 89 c2 4a 01 1d ?? ?? ?? ?? 83 ea ?? 31 c2 01 3d ?? ?? ?? ?? 4a 83 c2 ?? b8 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 89 30 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}