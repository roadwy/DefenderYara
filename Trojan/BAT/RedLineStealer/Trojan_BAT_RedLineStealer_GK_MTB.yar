
rule Trojan_BAT_RedLineStealer_GK_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {55 50 6c 52 54 78 73 6f 6a 76 6f 55 4b 79 59 30 68 6b 2e 47 59 4d 6e 49 37 67 51 65 51 45 65 75 34 4f 6d 36 74 } //01 00  UPlRTxsojvoUKyY0hk.GYMnI7gQeQEeu4Om6t
		$a_81_1 = {73 30 35 41 55 70 44 46 57 4c 6c 58 48 64 48 78 58 71 2e 6f 69 76 43 77 55 4a 53 4e 69 65 68 6d 56 49 4f 41 68 } //01 00  s05AUpDFWLlXHdHxXq.oivCwUJSNiehmVIOAh
		$a_81_2 = {43 6f 72 72 61 6c 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Corral.g.resources
		$a_81_3 = {52 65 63 79 63 6c 65 20 42 69 6f 20 4c 61 62 20 54 6f 6f 6c } //01 00  Recycle Bio Lab Tool
		$a_81_4 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 } //00 00  Confuser.Core
	condition:
		any of ($a_*)
 
}