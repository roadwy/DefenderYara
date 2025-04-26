
rule Trojan_Win32_CatRat_B_MTB{
	meta:
		description = "Trojan:Win32/CatRat.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 8b 14 8d ?? ?? 00 10 81 ea ?? 00 00 00 8b 45 08 03 45 fc 88 10 e9 ?? ff ff ff } //1
		$a_03_1 = {ff ff ff 65 c6 45 ?? 6c c6 85 ?? ff ff ff 6e c6 45 ?? 32 c6 45 ?? 6f c6 45 ?? 75 c6 45 ?? 69 8d 85 ?? ff ff ff 50 ff 55 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}