
rule Trojan_Win32_DLLHijack_DJ_MTB{
	meta:
		description = "Trojan:Win32/DLLHijack.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e4 6c c6 45 e5 6f c6 45 e6 61 c6 45 e7 64 c6 45 e8 65 c6 45 e9 72 c6 45 ea 2e c6 45 eb 64 c6 45 ec 61 c6 45 ed 74 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}