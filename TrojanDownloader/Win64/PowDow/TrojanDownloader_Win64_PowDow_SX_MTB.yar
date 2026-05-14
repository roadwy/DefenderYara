
rule TrojanDownloader_Win64_PowDow_SX_MTB{
	meta:
		description = "TrojanDownloader:Win64/PowDow.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_80_0 = {52 6f 6f 74 32 42 79 70 61 73 73 } //Root2Bypass  20
		$a_80_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 69 65 78 20 28 20 69 72 6d 20 72 61 77 2e } //powershell iex ( irm raw.  10
	condition:
		((#a_80_0  & 1)*20+(#a_80_1  & 1)*10) >=30
 
}