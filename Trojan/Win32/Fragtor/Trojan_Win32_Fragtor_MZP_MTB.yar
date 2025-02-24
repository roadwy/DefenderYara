
rule Trojan_Win32_Fragtor_MZP_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.MZP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 8b d0 0f be c8 c1 ea 05 8a da 32 d0 22 d8 0f be d2 0f af d1 02 d8 22 da 32 d8 88 5c 04 ?? 40 3d 00 71 02 00 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}