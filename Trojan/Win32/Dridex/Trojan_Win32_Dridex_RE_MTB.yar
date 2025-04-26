
rule Trojan_Win32_Dridex_RE_MTB{
	meta:
		description = "Trojan:Win32/Dridex.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 1c 38 8b 2b 89 ce 31 ee 89 33 8d 5f 04 89 df 8b 5a 08 39 fb 77 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}