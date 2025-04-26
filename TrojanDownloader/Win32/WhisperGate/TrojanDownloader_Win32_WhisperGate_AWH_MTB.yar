
rule TrojanDownloader_Win32_WhisperGate_AWH_MTB{
	meta:
		description = "TrojanDownloader:Win32/WhisperGate.AWH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 45 f4 a0 b0 40 00 c7 45 f0 c4 b0 40 00 8b 45 10 89 44 24 10 8b 45 0c 89 44 24 0c 8b 45 08 89 44 24 08 8b 45 f0 89 44 24 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}