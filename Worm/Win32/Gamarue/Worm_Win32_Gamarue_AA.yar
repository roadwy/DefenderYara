
rule Worm_Win32_Gamarue_AA{
	meta:
		description = "Worm:Win32/Gamarue.AA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 1f 8b 15 ?? ?? ?? ?? 03 55 ?? 0f b6 02 33 45 ?? 03 45 fc 8b 0d ?? ?? ?? ?? 03 4d ?? 88 01 eb cd ff 15 ?? ?? ?? ?? 81 7d 14 ff ff ff 07 75 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}