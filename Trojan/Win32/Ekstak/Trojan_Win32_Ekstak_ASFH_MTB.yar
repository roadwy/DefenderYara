
rule Trojan_Win32_Ekstak_ASFH_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 20 53 56 57 68 ?? ?? 4c 00 6a 01 6a 00 ff 15 ?? ?? 4c 00 85 c0 } //4
		$a_03_1 = {55 8b ec 83 ec 08 68 ?? ?? 65 00 6a 01 6a 00 ff 15 ?? ?? 65 00 85 c0 } //4
		$a_01_2 = {41 00 6e 00 79 00 4d 00 65 00 64 00 69 00 61 00 50 00 6c 00 61 00 79 00 65 00 72 00 32 00 31 00 39 00 } //1 AnyMediaPlayer219
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4+(#a_01_2  & 1)*1) >=5
 
}