
rule Trojan_Win32_Shipup_GPA_MTB{
	meta:
		description = "Trojan:Win32/Shipup.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {ba 7a dc 1e 86 1d 2e 60 ce e0 02 01 33 73 49 83 72 70 61 0e 71 67 92 b2 80 f5 32 fe ab 62 bf 76 d9 e4 13 ab 73 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}