
rule Trojan_BAT_PDFConverter_MX_MTB{
	meta:
		description = "Trojan:BAT/PDFConverter.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4e 00 6f 00 74 00 41 00 57 00 6f 00 72 00 64 00 2e 00 65 00 78 00 65 00 } //1 NotAWord.exe
		$a_80_1 = {6d 6f 63 2e 6d 69 6d 69 74 6f 73 70 2e 70 61 6e } //moc.mimitosp.pan  1
		$a_80_2 = {70 73 6f 74 69 6d 69 6d 2e 63 6f 6d } //psotimim.com  1
		$a_00_3 = {43 00 53 00 49 00 52 00 45 00 4c 00 53 00 43 00 53 00 49 00 52 00 45 00 4c 00 53 00 } //1 CSIRELSCSIRELS
	condition:
		((#a_00_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}