
rule Trojan_Win32_LummaC_GZM_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d9 81 f1 ?? ?? ?? ?? 83 e3 ?? 01 db 29 cb 88 9c 14 ?? ?? ?? ?? 42 81 fa } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}