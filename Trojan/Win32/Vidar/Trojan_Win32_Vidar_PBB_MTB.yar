
rule Trojan_Win32_Vidar_PBB_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 83 0d ?? ?? ?? ?? ?? 8b c6 c1 e8 05 03 c3 03 ce 33 c8 31 4d 08 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 0c 8b 45 08 29 45 f8 8b 45 e4 29 45 fc ff 4d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}