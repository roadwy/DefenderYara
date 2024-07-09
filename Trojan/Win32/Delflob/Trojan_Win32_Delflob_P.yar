
rule Trojan_Win32_Delflob_P{
	meta:
		description = "Trojan:Win32/Delflob.P,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 45 e8 01 00 00 00 8d 45 ?? 8b 55 ?? 8b 4d ?? [0-20] 8a ?? ?? ff 8a 4d fb 32 d1 e8 ?? ?? ?? ff 8b 55 ?? 8d 45 f0 e8 ?? ?? ?? ff ff 45 e8 (4b|ff 4d ?? 75 90) 14 8d 45 ?? 8b 55 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}