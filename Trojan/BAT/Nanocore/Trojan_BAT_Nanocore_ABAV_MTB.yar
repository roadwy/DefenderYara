
rule Trojan_BAT_Nanocore_ABAV_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {11 12 11 0e 8f 90 01 03 01 25 47 7e 90 01 03 04 19 11 0e 5f 19 62 1f 1f 5f 63 d2 61 d2 52 11 0e 17 58 13 0e 11 0e 11 12 8e 69 33 d4 90 00 } //1
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_2 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //1 GetManifestResourceStream
		$a_01_3 = {24 39 31 30 33 61 61 30 33 2d 61 32 39 39 2d 34 38 37 36 2d 38 61 31 34 2d 63 32 31 31 38 38 65 30 39 61 62 39 } //1 $9103aa03-a299-4876-8a14-c21188e09ab9
		$a_01_4 = {41 64 76 61 6e 63 65 64 5f 48 74 6d 6c 5f 45 64 69 74 6f 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Advanced_Html_Editor.Resources.resources
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}