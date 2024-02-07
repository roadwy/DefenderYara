
rule Trojan_BAT_AsyncRAT_AK_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 ff b6 ff 09 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 9d 00 00 00 5e 04 00 00 4e 01 00 00 d6 13 } //02 00 
		$a_01_1 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 } //00 00  C:\Windows\Microsoft.NET\Framework
	condition:
		any of ($a_*)
 
}