
rule Trojan_Win32_LummaStealer_NKI_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 00 89 c1 8b 45 ?? ba ?? ?? ?? ?? f7 75 ?? 8b 45 ?? 01 d0 0f b6 00 31 c1 8b 55 ?? 8b 45 ?? 01 d0 89 ca 88 10 83 45 ?? ?? 8b 45 ?? 3b 45 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}