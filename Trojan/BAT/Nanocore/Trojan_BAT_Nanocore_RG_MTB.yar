
rule Trojan_BAT_Nanocore_RG_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {6c 69 56 73 78 62 63 42 76 52 57 67 58 67 65 7a 42 45 7a 53 63 59 74 63 75 77 4f 56 4e 43 } //1 liVsxbcBvRWgXgezBEzScYtcuwOVNC
		$a_01_1 = {24 65 39 66 31 38 61 33 30 2d 35 37 63 30 2d 34 33 66 30 2d 39 31 62 36 2d 30 37 39 36 62 36 38 31 30 31 39 30 } //1 $e9f18a30-57c0-43f0-91b6-0796b6810190
		$a_01_2 = {43 6f 6e 66 75 73 65 72 45 78 20 76 31 2e 30 2e 30 2d 33 38 2d 67 37 38 38 39 39 37 31 } //1 ConfuserEx v1.0.0-38-g7889971
		$a_01_3 = {43 6f 6d 70 75 74 65 48 61 73 68 } //1 ComputeHash
		$a_01_4 = {73 65 74 5f 4b 65 79 } //1 set_Key
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}