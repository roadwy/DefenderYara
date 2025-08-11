
rule Trojan_Win32_LummaStealer_CCJX_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 31 c5 33 1c ad ?? ?? ?? ?? 89 d8 c1 e8 ?? 83 e3 ?? c1 ef ?? 31 df } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}