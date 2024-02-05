
rule Trojan_Win32_ClipBanker_EM_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {8d 77 02 6a 31 5b 6a 30 5f 83 c6 02 33 c0 66 39 06 } //05 00 
		$a_01_1 = {8d 77 02 6a 30 5b 6a 31 5f 83 c6 02 33 c0 66 39 06 } //00 00 
	condition:
		any of ($a_*)
 
}