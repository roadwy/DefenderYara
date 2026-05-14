
rule Trojan_BAT_Typhon_KK_MTB{
	meta:
		description = "Trojan:BAT/Typhon.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 07 00 00 "
		
	strings :
		$a_01_0 = {46 69 72 65 66 6f 78 4c 6f 67 69 6e 45 6e 74 72 79 } //1 FirefoxLoginEntry
		$a_01_1 = {3c 43 6f 6c 6c 65 63 74 42 72 6f 77 73 65 72 44 61 74 61 3e } //2 <CollectBrowserData>
		$a_01_2 = {3c 43 6f 6c 6c 65 63 74 46 69 72 65 66 6f 78 50 61 73 73 77 6f 72 64 73 3e } //3 <CollectFirefoxPasswords>
		$a_01_3 = {3c 43 6f 6c 6c 65 63 74 4c 6f 67 69 6e 44 61 74 61 3e } //4 <CollectLoginData>
		$a_01_4 = {3c 43 6f 6c 6c 65 63 74 57 61 6c 6c 65 74 73 3e } //5 <CollectWallets>
		$a_01_5 = {3c 43 6f 6c 6c 65 63 74 57 65 62 44 61 74 61 3e } //6 <CollectWebData>
		$a_01_6 = {3c 44 6f 49 6e 6a 65 63 74 3e } //7 <DoInject>
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*4+(#a_01_4  & 1)*5+(#a_01_5  & 1)*6+(#a_01_6  & 1)*7) >=28
 
}