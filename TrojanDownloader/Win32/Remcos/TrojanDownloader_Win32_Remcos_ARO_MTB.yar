
rule TrojanDownloader_Win32_Remcos_ARO_MTB{
	meta:
		description = "TrojanDownloader:Win32/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 db 03 c3 8b 1d ?? ?? ?? ?? 01 18 8d 99 5e 03 00 00 69 db 91 03 00 00 8d 04 08 83 01 02 4a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}