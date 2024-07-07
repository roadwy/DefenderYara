
rule Trojan_Win32_Gozi_RG_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 06 03 d1 a1 90 01 04 c1 e0 06 03 d0 8b 0d 90 01 04 0f af 0d 90 01 04 c1 e1 06 2b d1 a1 90 01 04 c1 e0 06 03 d0 8b 0d 90 01 04 c1 e1 06 2b d1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}