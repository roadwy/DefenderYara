
rule Trojan_Script_ShortSeek_GA_dha{
	meta:
		description = "Trojan:Script/ShortSeek.GA!dha,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-30] 2e 00 [0-30] 2e 00 77 00 6f 00 72 00 6b 00 65 00 72 00 73 00 2e 00 64 00 65 00 76 00 2f 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}