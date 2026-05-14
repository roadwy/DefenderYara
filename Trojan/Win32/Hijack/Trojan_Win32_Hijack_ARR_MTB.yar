
rule Trojan_Win32_Hijack_ARR_MTB{
	meta:
		description = "Trojan:Win32/Hijack.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 16 8b f9 8b e9 32 10 40 88 16 83 ef } //15
		$a_81_1 = {50 4f 53 47 72 61 62 62 65 72 5f 6d 75 74 61 74 65 64 2e 65 78 65 } //5 POSGrabber_mutated.exe
	condition:
		((#a_01_0  & 1)*15+(#a_81_1  & 1)*5) >=20
 
}