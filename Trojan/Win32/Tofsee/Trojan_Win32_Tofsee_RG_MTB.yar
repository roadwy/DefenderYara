
rule Trojan_Win32_Tofsee_RG_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 45 ab c1 e0 04 88 45 ab 0f b6 4d ab 81 e1 c0 00 00 00 88 4d ab 0f b6 55 a8 0f b6 45 ab 0b d0 88 55 a8 8a 4d a7 88 4d ab 0f b6 55 ab c1 e2 06 88 55 ab } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}