
rule Trojan_Win32_Mokes_RG_MTB{
	meta:
		description = "Trojan:Win32/Mokes.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 b9 04 00 00 00 f7 f1 8b 45 10 0f b6 0c 10 8b 55 08 03 55 ?? 0f b6 02 33 c1 8b 4d 08 03 4d ?? 88 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}