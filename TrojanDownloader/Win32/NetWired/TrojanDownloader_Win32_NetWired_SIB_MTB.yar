
rule TrojanDownloader_Win32_NetWired_SIB_MTB{
	meta:
		description = "TrojanDownloader:Win32/NetWired.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {44 45 5f 4b 6d 6e 6e 65 63 74 5a } //1 DE_KmnnectZ
		$a_00_1 = {61 6e 65 54 2e 44 4c 4c } //1 aneT.DLL
		$a_03_2 = {f7 e2 c1 e8 ?? 89 d1 81 e2 ?? ?? ?? ?? c1 e9 ?? 8d 14 92 01 c2 89 c8 83 c8 ?? 88 07 89 d0 83 f9 01 83 df ff c1 e8 ?? 81 e2 ?? ?? ?? ?? 09 c1 83 c8 ?? 88 07 8d 04 92 8d 14 92 83 f9 01 83 df ff c1 e8 ?? 81 e2 ?? ?? ?? ?? 09 c1 83 c8 ?? 88 07 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}