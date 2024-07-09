
rule Trojan_Win32_VecStealer_LK_MTB{
	meta:
		description = "Trojan:Win32/VecStealer.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 0c 00 00 00 f7 f9 8b 45 ?? 0f b6 0c 10 8b 55 ?? 03 55 ?? 0f b6 02 33 c1 8b 4d ?? 03 4d fc 88 01 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}