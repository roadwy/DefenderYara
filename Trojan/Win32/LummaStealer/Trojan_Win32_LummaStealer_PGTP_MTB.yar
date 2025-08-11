
rule Trojan_Win32_LummaStealer_PGTP_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PGTP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 74 04 e6 e6 ea f1 38 e8 3c ?? 02 8d ?? ?? ?? ?? a1 ?? ?? ?? ?? 84 c0 74 ?? af e1 ?? 24 ?? 8b c7 48 80 38 ?? 5d e0 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}