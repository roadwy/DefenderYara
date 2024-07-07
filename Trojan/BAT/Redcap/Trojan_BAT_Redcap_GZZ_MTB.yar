
rule Trojan_BAT_Redcap_GZZ_MTB{
	meta:
		description = "Trojan:BAT/Redcap.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 60 0a 6f 90 01 03 06 06 20 90 01 04 5e 0a 28 90 01 03 06 20 90 01 04 06 59 0a 0b 20 90 01 04 06 61 39 90 01 04 02 7b 90 01 04 02 20 90 01 04 06 60 0a 02 7b 90 01 04 6f 90 01 03 06 06 20 90 01 04 58 0a 07 90 00 } //10
		$a_80_1 = {70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 48 74 50 38 4e 30 30 59 } //pastebin.com/raw/HtP8N00Y  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}