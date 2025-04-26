
rule TrojanDownloader_Win32_Small_ARAQ_MTB{
	meta:
		description = "TrojanDownloader:Win32/Small.ARAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c1 6a 03 99 5f f7 ff 80 c2 02 00 91 28 41 40 00 41 3b ce 7c ea } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}