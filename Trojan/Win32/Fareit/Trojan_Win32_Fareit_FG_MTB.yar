
rule Trojan_Win32_Fareit_FG_MTB{
	meta:
		description = "Trojan:Win32/Fareit.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {15 43 00 8c 19 43 00 5c 19 43 00 1c 1b 43 00 ec 1a 43 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}