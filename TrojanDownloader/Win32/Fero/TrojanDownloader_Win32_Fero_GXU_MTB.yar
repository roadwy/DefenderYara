
rule TrojanDownloader_Win32_Fero_GXU_MTB{
	meta:
		description = "TrojanDownloader:Win32/Fero.GXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 29 d0 83 f0 ?? 8d 05 ?? ?? ?? ?? 01 20 83 f0 ?? 48 89 d0 4a b9 02 00 00 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}