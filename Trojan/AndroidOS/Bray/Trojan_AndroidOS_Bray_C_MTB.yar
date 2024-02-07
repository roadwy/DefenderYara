
rule Trojan_AndroidOS_Bray_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Bray.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 42 41 50 42 51 67 4a 4f 42 63 4b 46 77 3d } //01 00  HBAPBQgJOBcKFw=
		$a_01_1 = {41 78 51 50 43 77 49 44 43 52 41 47 42 77 63 3d } //01 00  AxQPCwIDCRAGBwc=
		$a_01_2 = {41 78 51 50 43 7a 49 42 46 43 59 65 4d 78 59 53 41 67 34 4d 43 67 6b 54 52 46 70 45 } //01 00  AxQPCzIBFCYeMxYSAg4MCgkTRFpE
		$a_01_3 = {41 77 45 2b 43 77 51 61 44 67 63 43 4f 77 59 65 47 42 41 61 42 44 4d 4f 41 41 3d 3d } //01 00  AwE+CwQaDgcCOwYeGBAaBDMOAA==
		$a_01_4 = {41 77 45 2b 43 42 45 7a 42 67 63 45 43 77 59 65 42 51 3d 3d } //00 00  AwE+CBEzBgcECwYeBQ==
	condition:
		any of ($a_*)
 
}