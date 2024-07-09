
rule Trojan_Win32_LummaStealer_CCHF_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c6 f7 f1 8b 45 ?? 46 8a 0c 02 8b 55 ?? 32 0c 3a 88 0f 8b 7d ?? 3b f3 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}