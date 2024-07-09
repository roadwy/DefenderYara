
rule TrojanDownloader_Win32_LummaStealer_CCFF_MTB{
	meta:
		description = "TrojanDownloader:Win32/LummaStealer.CCFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 ca 83 e2 ?? 0f b6 54 14 ?? 32 54 0e ?? 88 14 0e 8d 51 ?? 83 e2 ?? 0f b6 54 14 ?? 32 54 0e ?? 88 54 0e ?? 83 c1 ?? 39 c8 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}