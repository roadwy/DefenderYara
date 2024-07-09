
rule Trojan_Win32_Redline_VIJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.VIJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 8b 4c 24 ?? 8d 44 24 28 89 54 24 28 e8 ?? ?? ?? ?? 8b 44 24 24 31 44 24 10 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 57 57 57 ff 15 ?? ?? ?? ?? 8b 44 24 10 33 44 24 28 89 44 24 10 2b f0 8b 44 24 ?? 29 44 24 14 83 6c 24 ?? ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}