
rule Trojan_Win32_Trickbot_STO{
	meta:
		description = "Trojan:Win32/Trickbot.STO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {73 74 61 72 74 20 43 72 61 77 6c 65 72 54 68 72 65 61 64 } //start CrawlerThread  1
		$a_80_1 = {74 65 6d 70 5c 6f 77 61 2e 6c 6f 67 } //temp\owa.log  1
		$a_80_2 = {46 69 6e 64 53 75 62 64 6f 6d 61 69 6e 73 28 29 } //FindSubdomains()  1
		$a_80_3 = {53 63 61 6e 53 65 6e 64 28 29 } //ScanSend()  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}