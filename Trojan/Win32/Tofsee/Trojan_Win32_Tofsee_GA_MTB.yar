
rule Trojan_Win32_Tofsee_GA_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 ec 84 08 00 00 a1 90 01 04 33 c4 89 84 24 80 08 00 00 8b 84 24 88 08 00 00 53 55 8b 28 56 33 db 81 3d 90 01 04 ab 07 00 00 57 8b 78 04 89 44 24 68 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}