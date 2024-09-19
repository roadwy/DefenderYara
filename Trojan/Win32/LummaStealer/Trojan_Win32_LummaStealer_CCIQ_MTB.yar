
rule Trojan_Win32_LummaStealer_CCIQ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 07 cb 65 fa 63 c7 47 ?? e5 61 f0 6f c7 47 ?? f2 6d b1 6b c7 47 ?? b4 69 ba 57 c7 47 ?? fa 55 c0 53 c7 47 ?? c6 51 50 5f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}