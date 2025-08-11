
rule Trojan_BAT_TeapotStealer_CH_MTB{
	meta:
		description = "Trojan:BAT/TeapotStealer.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 07 00 00 "
		
	strings :
		$a_01_0 = {3c 47 65 74 41 6c 6c 43 6f 6f 6b 69 65 73 3e } //2 <GetAllCookies>
		$a_01_1 = {3c 47 65 74 44 65 62 75 67 57 73 55 72 6c 3e } //2 <GetDebugWsUrl>
		$a_01_2 = {3c 50 72 6f 63 65 73 73 43 68 72 6f 6d 69 75 6d 43 6f 6f 6b 69 65 73 3e } //2 <ProcessChromiumCookies>
		$a_01_3 = {3c 50 72 6f 63 65 73 73 46 69 72 65 66 6f 78 43 6f 6f 6b 69 65 73 3e } //2 <ProcessFirefoxCookies>
		$a_01_4 = {3c 43 6f 6c 6c 65 63 74 41 6e 64 55 70 6c 6f 61 64 43 6f 6f 6b 69 65 73 3e } //2 <CollectAndUploadCookies>
		$a_01_5 = {3c 43 6f 6c 6c 65 63 74 50 61 73 73 77 6f 72 64 73 3e } //2 <CollectPasswords>
		$a_01_6 = {57 61 6c 6c 65 74 } //1 Wallet
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1) >=13
 
}