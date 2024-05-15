
rule Trojan_Win32_DCRat_D_MTB{
	meta:
		description = "Trojan:Win32/DCRat.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {32 cb 52 5a c1 f2 90 01 01 d0 c9 f6 d9 80 c1 90 01 01 80 f1 90 01 01 32 d9 c1 ca 90 01 01 02 d2 0f be c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}