
rule Trojan_Win32_MSILInjector_GZ_MTB{
	meta:
		description = "Trojan:Win32/MSILInjector.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //01 00  aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
		$a_81_1 = {6d 73 63 6f 72 65 65 2e 64 6c 6c } //01 00  mscoree.dll
		$a_81_2 = {4b 6b 6e 69 66 65 72 73 20 52 65 69 6e 74 65 67 72 61 74 69 6f 6e 73 } //01 00  Kknifers Reintegrations
		$a_81_3 = {5f 2e 70 64 62 } //01 00  _.pdb
		$a_81_4 = {64 31 37 62 34 31 63 39 2d 33 39 35 35 2d 34 38 39 30 2d 39 35 62 38 2d 38 38 37 61 61 63 30 30 36 65 30 62 } //00 00  d17b41c9-3955-4890-95b8-887aac006e0b
	condition:
		any of ($a_*)
 
}