
rule Trojan_Win32_Rozena_SPXR_MTB{
	meta:
		description = "Trojan:Win32/Rozena.SPXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 8d 50 01 89 55 f4 0f b6 00 0f be c0 34 ff 89 c2 8b 45 e8 89 44 24 04 89 14 24 e8 ?? ?? ?? ?? 8b 45 f0 8d 50 ff 89 55 f0 85 c0 75 d1 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}