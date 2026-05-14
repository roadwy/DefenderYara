
rule Trojan_O97M_AWSCredMacroStealer_A{
	meta:
		description = "Trojan:O97M/AWSCredMacroStealer.A,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 77 65 62 68 6f 6f 6b 2e 73 69 74 65 2f 36 64 36 31 39 39 38 62 2d 61 38 66 62 2d 34 65 35 37 2d 38 37 34 64 2d 64 32 65 39 61 33 38 62 64 61 37 } //5 https://webhook.site/6d61998b-a8fb-4e57-874d-d2e9a38bda7
		$a_01_1 = {68 74 74 70 3a 2f 2f 31 36 39 2e 32 35 34 2e 31 36 39 2e 32 35 34 2f 6c 61 74 65 73 74 2f 6d 65 74 61 2d 64 61 74 61 2f 69 61 6d 2f 73 65 63 75 72 69 74 79 2d 63 72 65 64 65 6e 74 69 61 6c 73 } //5 http://169.254.169.254/latest/meta-data/iam/security-credentials
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}