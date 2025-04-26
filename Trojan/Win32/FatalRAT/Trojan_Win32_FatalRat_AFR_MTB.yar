
rule Trojan_Win32_FatalRat_AFR_MTB{
	meta:
		description = "Trojan:Win32/FatalRat.AFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 45 dc 33 36 30 74 c7 45 e0 72 61 79 2e 66 c7 45 e4 65 78 c7 45 c0 41 44 56 41 c7 45 c4 50 49 33 32 c7 45 c8 2e 64 6c 6c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}