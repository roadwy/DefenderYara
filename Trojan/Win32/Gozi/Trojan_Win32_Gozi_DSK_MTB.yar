
rule Trojan_Win32_Gozi_DSK_MTB{
	meta:
		description = "Trojan:Win32/Gozi.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {bd a7 19 67 3b 2b ee 89 2d ?? ?? ?? ?? 2b d1 83 c2 50 66 01 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 74 24 10 81 c2 f0 e6 76 01 89 16 81 3d ?? ?? ?? ?? fa ff 00 00 89 15 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}