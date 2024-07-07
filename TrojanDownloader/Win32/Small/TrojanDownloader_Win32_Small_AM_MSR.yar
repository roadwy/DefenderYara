
rule TrojanDownloader_Win32_Small_AM_MSR{
	meta:
		description = "TrojanDownloader:Win32/Small.AM!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c9 33 db 68 90 01 04 e8 90 01 04 80 b1 90 01 05 41 8b d9 3b d8 74 90 01 01 eb f0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}