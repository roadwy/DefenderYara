
rule Trojan_BAT_AsyncRAT_AJ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 d4 02 e8 c9 03 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 31 00 00 00 0c 00 00 00 2b 00 00 00 65 } //02 00 
		$a_01_1 = {73 65 72 76 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}