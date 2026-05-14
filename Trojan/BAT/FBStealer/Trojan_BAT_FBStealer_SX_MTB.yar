
rule Trojan_BAT_FBStealer_SX_MTB{
	meta:
		description = "Trojan:BAT/FBStealer.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3d 00 3d 00 06 00 00 "
		
	strings :
		$a_80_0 = {56 4e 4c 49 4b 45 32 34 37 2e 4e 45 54 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //VNLIKE247.NET.Properties.Resources  30
		$a_80_1 = {5c 5c 22 71 65 69 64 5c 5c 22 3a 5c 5c 22 28 5c 64 2b 29 5c 5c 22 } //\\"qeid\\":\\"(\d+)\\"  10
		$a_80_2 = {6c 6f 67 6f 75 74 5f 68 61 73 68 22 3a 22 28 2e 2a 3f 29 22 } //logout_hash":"(.*?)"  10
		$a_80_3 = {63 6f 70 79 64 6f 6e 67 62 6f 69 64 65 6e } //copydongboiden  5
		$a_80_4 = {63 72 65 64 65 6e 74 69 61 6c 73 32 2e 6a 73 6f 6e } //credentials2.json  5
		$a_80_5 = {77 77 77 2e 66 61 63 65 62 6f 6f 6b 2e 63 6f 6d 2f 6c 6f 67 69 6e } //www.facebook.com/login  1
	condition:
		((#a_80_0  & 1)*30+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*5+(#a_80_4  & 1)*5+(#a_80_5  & 1)*1) >=61
 
}