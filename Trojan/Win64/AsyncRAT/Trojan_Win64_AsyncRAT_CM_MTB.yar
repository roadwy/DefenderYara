
rule Trojan_Win64_AsyncRAT_CM_MTB{
	meta:
		description = "Trojan:Win64/AsyncRAT.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {37 80 74 24 90 01 01 38 80 74 24 90 01 01 39 80 74 24 90 01 01 3a 80 74 24 90 01 01 3b 80 74 24 90 01 01 3c 80 74 24 90 01 01 3d 34 3e c6 44 24 90 01 01 31 88 44 24 90 01 01 48 8d 44 24 90 01 01 49 ff c0 42 80 3c 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}