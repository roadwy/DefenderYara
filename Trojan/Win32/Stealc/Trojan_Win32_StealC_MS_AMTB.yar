
rule Trojan_Win32_StealC_MS_AMTB{
	meta:
		description = "Trojan:Win32/StealC.MS!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_02_0 = {68 00 74 74 70 00 3a 00 2f 00 2f 00 36 00 32 00 2e 00 36 00 30 00 2e 00 32 00 32 00 36 00 2e 00 32 00 34 00 38 00 3a 00 [0-04] 2f 00 [0-4b] 5f 00 [0-04] 62 00 75 00 69 00 6c 00 64 00 2e 00 62 00 69 00 6e 00 } //4
		$a_02_1 = {68 74 74 70 3a 2f 2f 36 32 2e 36 30 2e 32 32 36 2e 32 34 38 3a [0-04] 2f [0-4b] 5f [0-04] 62 75 69 6c 64 2e 62 69 6e } //4
		$a_80_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 43 61 63 68 65 46 69 6c 65 } //URLDownloadToCacheFile  3
	condition:
		((#a_02_0  & 1)*4+(#a_02_1  & 1)*4+(#a_80_2  & 1)*3) >=7
 
}