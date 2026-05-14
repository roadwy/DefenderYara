
rule Trojan_Win32_Hijacker_MKZ_MTB{
	meta:
		description = "Trojan:Win32/Hijacker.MKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 16 8b f9 8b e9 32 10 40 88 16 83 ef 01 75 f6 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}