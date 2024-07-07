
rule Trojan_Win32_QQPass_GZZ_MTB{
	meta:
		description = "Trojan:Win32/QQPass.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {1e ec 16 41 00 00 1e a4 1a 41 00 00 1e 0c ee 42 00 00 1e 14 ed 42 00 00 1e 30 1b 41 00 00 1e 40 1b 41 00 00 1e } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}