
rule Trojan_Win32_DllCheck_A_MSR{
	meta:
		description = "Trojan:Win32/DllCheck.A!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 10 80 ca 60 03 da d1 e3 03 45 10 8a 08 84 c9 e0 ee 33 c0 8b 4d 0c 3b d9 74 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}