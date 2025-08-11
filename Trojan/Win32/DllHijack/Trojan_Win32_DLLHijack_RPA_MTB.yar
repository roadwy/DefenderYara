
rule Trojan_Win32_DLLHijack_RPA_MTB{
	meta:
		description = "Trojan:Win32/DLLHijack.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 ec 33 c6 45 ed 38 c6 45 ee 2e c6 45 ef 31 c6 45 f0 38 c6 45 f1 31 c6 45 f2 2e c6 45 f3 34 c6 45 f4 32 c6 45 f5 2e c6 45 f6 31 c6 45 f7 32 c6 45 f8 37 c6 45 f9 00 c6 85 28 fc ff ff 73 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}