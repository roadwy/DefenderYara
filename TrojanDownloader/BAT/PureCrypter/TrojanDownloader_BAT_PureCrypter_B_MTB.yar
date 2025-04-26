
rule TrojanDownloader_BAT_PureCrypter_B_MTB{
	meta:
		description = "TrojanDownloader:BAT/PureCrypter.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 06 1f 0c 58 4a 18 5b 1f 10 07 06 1f 0c 58 4a 18 6f } //2 ؉ట䩘嬘ဟ؇ట䩘漘
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}