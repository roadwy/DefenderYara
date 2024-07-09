
rule TrojanDownloader_Win32_GuloaderCrypt_SK_MTB{
	meta:
		description = "TrojanDownloader:Win32/GuloaderCrypt.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {29 c9 0f ee ca 43 0f e4 ca 0b 0f 0f ee ca 31 d9 0f da ca 39 c1 75 e9 0f e4 ca 0f ee ca } //2
		$a_02_1 = {0f da ca 0f e4 ca 81 c1 ?? ?? ?? ?? 0f e4 ca 0f ee ca 81 e9 ?? ?? ?? ?? 0f da ca 0f ee ca 81 f1 ?? ?? ?? ?? 0f e4 ca 0f ee ca 0f e4 ca 0f e4 ca ff 31 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}