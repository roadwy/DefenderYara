
rule TrojanDownloader_Win32_Banload_ASU{
	meta:
		description = "TrojanDownloader:Win32/Banload.ASU,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}