
rule Trojan_Win32_AsyncRAT_C_MTB{
	meta:
		description = "Trojan:Win32/AsyncRAT.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {2b d0 8a 82 90 01 04 88 44 0c 30 41 81 f9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}