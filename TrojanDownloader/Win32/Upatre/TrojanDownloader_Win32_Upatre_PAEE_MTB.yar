
rule TrojanDownloader_Win32_Upatre_PAEE_MTB{
	meta:
		description = "TrojanDownloader:Win32/Upatre.PAEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 d0 83 e3 27 83 f3 c2 31 db 83 d3 53 f8 83 d8 01 } //1
		$a_03_1 = {6a 00 68 e8 03 00 00 6a ff ff 15 ?? ?? ?? ?? 83 d1 7a 31 3d ?? ?? ?? ?? 11 cb 83 0d ?? ?? ?? ?? 25 ff 0c 24 75 da } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}