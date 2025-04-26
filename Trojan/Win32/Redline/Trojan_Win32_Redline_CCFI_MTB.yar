
rule Trojan_Win32_Redline_CCFI_MTB{
	meta:
		description = "Trojan:Win32/Redline.CCFI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e8 61 c6 45 e9 43 c6 45 ea f8 c6 45 eb 19 c6 45 ec 37 c6 45 ed e2 c6 45 ee 0d c6 45 ef a0 c6 45 f0 39 c6 45 f1 2f c6 45 f2 2d c6 45 f3 53 c6 45 f4 f2 c6 45 f5 29 c6 45 f6 36 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}