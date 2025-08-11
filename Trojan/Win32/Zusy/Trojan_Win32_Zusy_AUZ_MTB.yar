
rule Trojan_Win32_Zusy_AUZ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AUZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 55 e6 8b 45 f4 01 d0 0f b6 18 c7 04 24 1c e0 a4 6c e8 ?? ?? ?? ?? 8b 55 f4 01 d0 83 c0 0a 88 18 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}