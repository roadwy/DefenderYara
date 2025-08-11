
rule Trojan_Win32_LummaStealer_GAD_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c7 41 03 c5 99 f7 7c 24 ?? 8b 44 24 2c 8a 04 02 8b 54 24 ?? 32 c7 32 44 24 ?? 32 02 8b 54 24 ?? 88 04 17 47 8b c2 81 f9 07 01 00 00 0f 8c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}