
rule Trojan_Win32_CryptInject_RBB_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.RBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {56 69 72 74 66 90 01 06 75 61 c6 05 90 01 04 6c ff 15 90 09 0d 00 c6 05 90 01 04 6f 90 00 } //01 00 
		$a_02_1 = {7c 00 6c ff 15 90 09 35 00 c6 05 90 01 04 6f c6 05 90 01 04 56 c6 05 90 01 04 69 c6 05 90 01 04 72 c6 05 90 01 04 74 c6 05 90 01 04 75 c6 05 90 01 04 61 c6 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}