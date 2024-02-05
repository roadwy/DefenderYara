
rule Trojan_Win32_PsDownload_RD_MTB{
	meta:
		description = "Trojan:Win32/PsDownload.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {55 89 e5 81 ec 00 00 00 00 90 b8 00 00 00 00 50 b8 00 00 00 00 50 b8 10 20 40 00 50 b8 05 20 40 00 50 b8 00 20 40 00 50 b8 00 00 00 00 50 e8 3d 02 00 00 b8 00 00 00 00 c9 c3 } //01 00 
		$a_03_1 = {c1 e0 02 b9 00 90 01 01 40 00 01 c1 b8 00 90 01 01 40 00 39 c1 0f 84 1d 00 00 00 8b 45 fc 48 89 45 fc c1 e0 02 b9 00 90 01 01 40 00 01 c1 8b 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}