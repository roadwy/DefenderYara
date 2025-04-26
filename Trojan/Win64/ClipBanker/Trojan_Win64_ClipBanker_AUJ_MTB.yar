
rule Trojan_Win64_ClipBanker_AUJ_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.AUJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 8c 24 ea 00 00 00 30 8c 24 eb 00 00 00 30 8c 24 ec 00 00 00 30 8c 24 ed 00 00 00 30 8c 24 ee 00 00 00 30 8c 24 ef 00 00 00 32 d1 88 94 24 f0 00 00 00 } //1
		$a_01_1 = {43 68 72 6f 6d 69 75 6d 44 61 74 61 2e 65 78 65 } //1 ChromiumData.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}