
rule Trojan_BAT_ZgRAT_KAJ_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.KAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 4e 78 9b d7 bd c9 57 9f 09 f8 19 0a 88 90 63 79 23 46 23 f9 62 } //1
		$a_01_1 = {86 47 cb 7d d5 fb f4 8a 66 40 bf 84 88 c5 46 db 03 ce 14 cb f0 ac ec } //1
		$a_01_2 = {43 61 6e 64 69 64 61 74 65 2e 4c 69 73 74 } //1 Candidate.List
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}