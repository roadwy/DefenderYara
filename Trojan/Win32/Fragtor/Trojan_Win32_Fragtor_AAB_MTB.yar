
rule Trojan_Win32_Fragtor_AAB_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.AAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c8 8a 00 88 c1 8b 45 ?? 88 c3 8b 45 ?? 01 d8 0f b6 c0 8d 1c 85 00 00 00 00 8b 45 ?? 01 d8 8b 00 31 c8 88 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}