
rule Trojan_BAT_OsnoStealer_RDA_MTB{
	meta:
		description = "Trojan:BAT/OsnoStealer.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {36 61 38 39 66 65 63 38 2d 33 35 35 63 2d 34 34 30 38 2d 38 32 31 35 2d 62 66 66 62 63 33 63 39 38 39 34 30 } //1 6a89fec8-355c-4408-8215-bffbc3c98940
		$a_01_1 = {43 72 61 63 6b 65 64 20 56 65 6e 6f 6d 20 52 6f 6f 74 6b 69 74 } //1 Cracked Venom Rootkit
		$a_81_2 = {44 65 70 6c 6f 79 6d 65 6e 74 4d 65 74 61 64 61 74 61 } //1 DeploymentMetadata
		$a_01_3 = {4c 4b 4e 46 71 77 64 4d 43 6b 49 51 73 46 43 68 71 6c 63 6b 61 4d 49 44 79 42 43 6e } //1 LKNFqwdMCkIQsFChqlckaMIDyBCn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}