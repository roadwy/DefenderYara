
rule Trojan_Win32_Reline_RWA_MTB{
	meta:
		description = "Trojan:Win32/Reline.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3d 77 6e 7a 70 75 ?? 8b 45 ?? 0f b6 04 06 89 45 ?? 8b 45 ?? 01 c8 89 45 ?? b8 db 35 2d b0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}