
rule Trojan_Win32_Ursnif_ASF_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.ASF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 69 74 2e 64 6c 6c 00 42 72 65 61 6b 67 6f 6f 64 00 42 72 69 67 68 74 00 43 6f 61 73 74 6d 69 6e 64 00 53 6f 6c 64 69 65 72 6d 61 67 6e 65 74 00 53 79 6d 62 6f 6c 73 6c 69 70 } //00 00 
	condition:
		any of ($a_*)
 
}