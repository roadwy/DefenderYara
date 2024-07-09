
rule Trojan_Win32_Stealer_GGL_MTB{
	meta:
		description = "Trojan:Win32/Stealer.GGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {c6 07 07 bf ?? ?? ?? ?? d5 bb 28 ee 1a 32 89 eb 38 0c 20 31 fa 09 ce } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}