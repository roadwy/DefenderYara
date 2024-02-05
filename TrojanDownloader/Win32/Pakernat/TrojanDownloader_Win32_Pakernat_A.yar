
rule TrojanDownloader_Win32_Pakernat_A{
	meta:
		description = "TrojanDownloader:Win32/Pakernat.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {ba 00 00 ad de 8b fe 66 ba ce fa 8a 06 46 32 c2 83 ea 06 aa 83 c2 f9 e2 f2 } //00 00 
	condition:
		any of ($a_*)
 
}