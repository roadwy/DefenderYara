
rule Trojan_Win32_Tracur_AS{
	meta:
		description = "Trojan:Win32/Tracur.AS,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {64 6e 73 65 72 72 6f 72 64 69 61 67 6f 66 66 5f 77 65 62 6f 63 2e 68 74 6d } //1 dnserrordiagoff_weboc.htm
		$a_01_1 = {64 6f 6e 79 61 2d 65 2d 65 71 74 65 73 61 64 2e 63 6f 6d } //1 donya-e-eqtesad.com
		$a_01_2 = {22 65 6e 74 65 72 70 72 69 73 65 5f 73 74 6f 72 65 5f 6e 61 6d 65 22 3a 20 22 44 65 66 61 75 6c 74 22 2c 20 22 65 6e 74 65 72 70 72 69 73 65 5f 73 74 6f 72 65 5f 75 72 6c 22 3a 20 22 2e 22 } //1 "enterprise_store_name": "Default", "enterprise_store_url": "."
		$a_01_3 = {54 46 61 6b 65 52 65 66 65 72 72 65 72 } //1 TFakeReferrer
		$a_01_4 = {2f 6c 6f 67 69 6e 2f 20 2f 74 77 65 65 74 2f 20 61 63 74 69 6f 6e 3d 65 6d 62 65 64 2d 66 6c 61 73 68 } //1 /login/ /tweet/ action=embed-flash
		$a_03_5 = {5f 42 47 46 49 4c 45 5f [0-0f] 5f 43 53 46 49 4c 45 5f } //1
		$a_01_6 = {0f b6 44 18 ff 8b d6 81 e2 ff 00 00 00 33 c2 83 f8 07 7d 0f 8b 17 b9 01 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}