
rule Trojan_Win32_LummaStealer_GTD_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 34 08 8b 45 ?? 8b 4d ?? 0f b6 14 08 31 f2 88 14 08 8b 45 ?? 83 c0 ?? 89 45 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}