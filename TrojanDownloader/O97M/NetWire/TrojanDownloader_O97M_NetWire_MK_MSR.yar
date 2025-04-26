
rule TrojanDownloader_O97M_NetWire_MK_MSR{
	meta:
		description = "TrojanDownloader:O97M/NetWire.MK!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_80_0 = {6c 6f 61 64 22 68 74 74 70 3a 2f 2f 6d 6f 6f 6e 73 68 69 6e 65 2d 6d 68 74 2e 62 65 73 74 2f 63 68 72 6f 6d 65 2e 6a 70 67 22 } //load"http://moonshine-mht.best/chrome.jpg"  1
	condition:
		((#a_80_0  & 1)*1) >=1
 
}