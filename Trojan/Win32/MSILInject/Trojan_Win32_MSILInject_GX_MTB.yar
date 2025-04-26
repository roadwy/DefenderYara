
rule Trojan_Win32_MSILInject_GX_MTB{
	meta:
		description = "Trojan:Win32/MSILInject.GX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //1 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
		$a_01_1 = {64 31 37 62 34 31 63 39 2d 33 39 35 35 2d 34 38 39 30 2d 39 35 62 38 2d 38 38 37 61 61 63 30 30 36 65 30 62 } //1 d17b41c9-3955-4890-95b8-887aac006e0b
		$a_01_2 = {5f 2e 70 64 62 } //1 _.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}