
rule Trojan_AndroidOS_Fakeapp_V{
	meta:
		description = "Trojan:AndroidOS/Fakeapp.V,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 4d 39 7a 7a 76 63 6e 2f 4d 51 73 67 6c 63 44 6f 53 6e 52 65 41 3d 3d } //01 00  aM9zzvcn/MQsglcDoSnReA==
		$a_01_1 = {63 6f 6d 2e 61 70 6b 6c 6b 77 65 73 2e 64 61 73 6d 77 6c 72 38 } //00 00  com.apklkwes.dasmwlr8
	condition:
		any of ($a_*)
 
}