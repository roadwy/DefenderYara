
rule Trojan_Win64_Dridex_MV_MTB{
	meta:
		description = "Trojan:Win64/Dridex.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {73 64 6d 66 7c 65 72 2e 70 64 62 } //sdmf|er.pdb  3
		$a_80_1 = {55 6e 65 6e 61 62 6c 65 52 6f 75 74 65 72 } //UnenableRouter  3
		$a_80_2 = {47 65 74 52 54 54 41 6e 64 48 6f 70 43 6f 75 6e 74 } //GetRTTAndHopCount  3
		$a_80_3 = {50 61 74 68 49 73 55 4e 43 53 65 72 76 65 72 53 68 61 72 65 57 } //PathIsUNCServerShareW  3
		$a_80_4 = {76 75 6c 6e 65 72 61 62 69 6c 69 74 69 65 73 2e 63 6f 6e 67 72 61 74 75 6c 61 74 65 64 50 6c 61 79 65 72 2e 72 65 61 73 6f 6e 69 6e 67 41 52 75 72 61 53 69 73 62 } //vulnerabilities.congratulatedPlayer.reasoningARuraSisb  3
		$a_80_5 = {44 73 45 6e 75 6d 65 72 61 74 65 44 6f 6d 61 69 6e 54 72 75 73 74 73 57 } //DsEnumerateDomainTrustsW  3
		$a_80_6 = {47 65 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 49 6e 66 6f 41 } //GetUrlCacheEntryInfoA  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}