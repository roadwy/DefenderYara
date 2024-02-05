
rule TrojanDownloader_Win32_Raccoon_AKL_MTB{
	meta:
		description = "TrojanDownloader:Win32/Raccoon.AKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {bd a0 ac aa bc bc cf 99 a6 bd bb ba ae a3 9f bd a0 bb aa ac bb cf 99 a6 bd bb ba ae a3 8e } //00 00 
	condition:
		any of ($a_*)
 
}