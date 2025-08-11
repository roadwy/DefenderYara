
rule Trojan_Win32_DLLHijack_DF_MTB{
	meta:
		description = "Trojan:Win32/DLLHijack.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 34 0f 02 de 8a 14 1f 88 14 0f 88 34 1f 02 d6 0f b6 d2 8a 14 17 8a 0c 06 32 ca 5a 88 0c 02 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}