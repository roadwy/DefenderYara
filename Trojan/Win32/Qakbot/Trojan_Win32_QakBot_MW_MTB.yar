
rule Trojan_Win32_QakBot_MW_MTB{
	meta:
		description = "Trojan:Win32/QakBot.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {85 c0 74 3b 8b [0-03] 3b [0-05] 72 02 eb 2e 8b [0-03] 03 [0-03] 8b [0-03] 03 [0-03] 68 [0-04] ff [0-05] 03 [0-03] 8b [0-03] 8a [0-03] 88 [0-03] 8b [0-03] 83 [0-03] 89 [0-03] eb } //1
		$a_02_1 = {89 11 33 c0 e9 90 0a 28 00 a1 [0-04] c7 05 [0-08] 01 05 [0-06] 8b 0d [0-04] 8b 15 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}