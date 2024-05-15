
rule Trojan_Win64_AsyncRAT_SA_MTB{
	meta:
		description = "Trojan:Win64/AsyncRAT.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 0f b6 01 83 fa 90 01 01 0f 47 c8 49 ff c1 0f b6 d1 2b da 8b c2 83 c8 90 01 01 c1 c3 90 01 01 0f af c2 8d 04 40 33 d8 49 83 ee 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}