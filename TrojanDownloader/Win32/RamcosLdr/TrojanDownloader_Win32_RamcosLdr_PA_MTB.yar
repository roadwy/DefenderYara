
rule TrojanDownloader_Win32_RamcosLdr_PA_MTB{
	meta:
		description = "TrojanDownloader:Win32/RamcosLdr.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {40 4d 61 64 63 72 79 70 74 40 44 65 63 72 79 70 74 41 } //1 @Madcrypt@DecryptA
		$a_01_1 = {40 4d 61 64 63 72 79 70 74 40 45 6e 63 72 79 70 74 41 } //1 @Madcrypt@EncryptA
		$a_03_2 = {8b 45 c0 40 89 45 c0 8b 45 ?? 83 c0 04 89 45 ?? 8b 45 ?? 3b 45 ?? 73 ?? 8b 45 ?? 8b 00 03 45 ?? 8b 4d ?? 89 01 eb ?? 8b 45 ?? 8b 40 4c 03 45 ?? 89 45 ?? 8b 45 ?? 40 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*3) >=5
 
}