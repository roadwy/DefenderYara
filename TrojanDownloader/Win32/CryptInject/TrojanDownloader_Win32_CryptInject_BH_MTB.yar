
rule TrojanDownloader_Win32_CryptInject_BH_MTB{
	meta:
		description = "TrojanDownloader:Win32/CryptInject.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 6f 77 6e 2e 32 31 31 39 35 2e 63 6f 6d 2f 6a 6d 78 2e 74 78 74 } //1 down.21195.com/jmx.txt
		$a_01_1 = {7a 68 65 67 65 68 61 69 7a 68 65 6e 62 7a 64 61 } //1 zhegehaizhenbzda
		$a_01_2 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //1 CreateMutexA
		$a_01_3 = {55 50 58 30 } //1 UPX0
		$a_01_4 = {55 50 58 31 } //1 UPX1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}