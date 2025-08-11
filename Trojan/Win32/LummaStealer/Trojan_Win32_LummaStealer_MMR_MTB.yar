
rule Trojan_Win32_LummaStealer_MMR_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 2c d8 8b 32 8b 7a 04 89 34 2a 89 7c 2a 04 43 8d 69 ff 39 eb 7c e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}