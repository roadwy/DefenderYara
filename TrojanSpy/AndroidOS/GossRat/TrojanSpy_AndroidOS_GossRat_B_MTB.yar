
rule TrojanSpy_AndroidOS_GossRat_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/GossRat.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 61 64 65 72 61 74 77 65 62 } //01 00  saderatweb
		$a_00_1 = {2f 53 6d 73 4d 65 73 73 61 67 65 } //01 00  /SmsMessage
		$a_00_2 = {77 65 62 2e 63 6c 69 63 6b } //00 00  web.click
	condition:
		any of ($a_*)
 
}