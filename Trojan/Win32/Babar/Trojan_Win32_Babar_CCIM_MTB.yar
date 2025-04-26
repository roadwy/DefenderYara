
rule Trojan_Win32_Babar_CCIM_MTB{
	meta:
		description = "Trojan:Win32/Babar.CCIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 1c 53 56 57 a0 48 d0 7c 00 32 05 49 d0 7c 00 a2 48 d0 7c 00 33 c9 8a 0d 43 d0 7c 00 c1 f9 03 83 c9 01 89 4d f0 db 45 f0 dc 3d ?? ?? 7d 00 dd 15 ?? ?? 7d 00 dc 05 ?? ?? 7c 00 dd 1d ?? ?? 7d 00 68 ?? ?? 7c 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}