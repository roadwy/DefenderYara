
rule Trojan_Win32_XWorm_BAA_MTB{
	meta:
		description = "Trojan:Win32/XWorm.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c7 f7 f6 03 cf 47 8a 44 15 ?? 8b 55 ?? 32 04 11 88 01 8b 4d ?? 3b fb 7c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}