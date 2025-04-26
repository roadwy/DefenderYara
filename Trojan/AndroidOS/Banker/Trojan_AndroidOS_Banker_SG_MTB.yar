
rule Trojan_AndroidOS_Banker_SG_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.SG!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 6d 2e 6d 69 6e 67 6c 65 32 2e 63 6f 6d 2f } //1 https://m.mingle2.com/
		$a_01_1 = {31 2e 32 2e 6d 61 6b 65 5f 6b 6e 6f 63 6b 5f 6f 6e 6c 79 } //1 1.2.make_knock_only
		$a_01_2 = {4d 54 51 7a 4d 6a 51 30 4d 54 55 36 4f 6a 6f 4f 63 72 73 47 4c 6f 4d 3d } //1 MTQzMjQ0MTU6OjoOcrsGLoM=
		$a_01_3 = {4e 6a 63 34 4e 54 55 78 4f 44 51 36 4f 6a 70 70 53 6b 6f 74 50 7a 76 4b 33 77 36 4c 41 6d 49 4e 31 41 3d 3d } //1 Njc4NTUxODQ6OjppSkotPzvK3w6LAmIN1A==
		$a_01_4 = {73 65 74 4a 61 76 61 53 63 72 69 70 74 43 61 6e 4f 70 65 6e 57 69 6e 64 6f 77 73 41 75 74 6f 6d 61 74 69 63 61 6c 6c 79 } //1 setJavaScriptCanOpenWindowsAutomatically
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}