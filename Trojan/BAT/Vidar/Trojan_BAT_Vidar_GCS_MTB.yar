
rule Trojan_BAT_Vidar_GCS_MTB{
	meta:
		description = "Trojan:BAT/Vidar.GCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {49 44 70 44 30 4b 4b 36 39 56 39 70 31 32 69 65 } //1 IDpD0KK69V9p12ie
		$a_01_1 = {59 4a 32 33 34 6a 38 68 54 5a 44 35 39 50 6f 4f } //1 YJ234j8hTZD59PoO
		$a_01_2 = {6b 5a 6e 68 54 4b 44 64 6b 6c 61 49 42 45 5a 6b 4f 61 63 6e } //1 kZnhTKDdklaIBEZkOacn
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_6 = {43 6f 6e 66 75 73 65 72 45 78 } //1 ConfuserEx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}