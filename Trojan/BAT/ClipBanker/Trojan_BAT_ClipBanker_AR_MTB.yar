
rule Trojan_BAT_ClipBanker_AR_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 02 07 6f ?? 00 00 0a 7e ?? 00 00 04 07 7e ?? 00 00 04 8e 69 5d 91 61 28 ?? 00 00 0a 6f ?? 00 00 0a 26 07 17 58 0b 07 02 6f } //2
		$a_01_1 = {41 64 64 43 6c 69 70 62 6f 61 72 64 46 6f 72 6d 61 74 4c 69 73 74 65 6e 65 72 } //1 AddClipboardFormatListener
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}