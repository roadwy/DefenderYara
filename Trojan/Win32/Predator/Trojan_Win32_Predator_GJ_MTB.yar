
rule Trojan_Win32_Predator_GJ_MTB{
	meta:
		description = "Trojan:Win32/Predator.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 5c 24 10 90 0a 50 00 8b 4b 04 [0-04] 89 4c 24 04 [0-04] 8b 4b 08 [0-04] 89 4c 24 08 [0-04] 83 c3 0c [0-04] 89 5c 24 0c [0-04] 33 db 8b 54 24 0c [0-04] 8b 12 33 d3 [0-04] 3b 54 24 08 [0-04] 74 ?? [0-04] 43 [0-04] [0-04] eb ?? 89 5c 24 10 } //1
		$a_02_1 = {ff e2 8b 04 24 90 0a 50 00 31 1c 0a [0-04] 3b 4c 24 04 [0-04] 7d ?? [0-04] [0-04] 83 c1 04 [0-04] eb ?? 8b e5 [0-04] 5d [0-04] 5b [0-04] ff e2 8b 04 24 [0-04] c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}