
rule Trojan_Win32_LummaStealer_GPPH_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GPPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 83 e0 03 8a 44 05 ?? 30 04 0b 41 3b ce 72 ef } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}