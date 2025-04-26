
rule Trojan_Win32_Kryptik_DER_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.DER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 79 05 8b e9 3b c5 77 15 3b d5 72 11 8b ce 85 f6 75 08 89 3d 0c 5e 72 00 eb 03 89 7e 05 8b f1 8b cf 85 c9 75 da } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}