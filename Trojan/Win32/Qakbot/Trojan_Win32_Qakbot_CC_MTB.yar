
rule Trojan_Win32_Qakbot_CC_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 5f 63 6d 73 31 35 46 69 78 65 64 31 36 74 6f 44 6f 75 62 6c 65 40 34 } //01 00  L_cms15Fixed16toDouble@4
		$a_01_1 = {4c 5f 63 6d 73 43 72 65 61 74 65 4d 75 74 65 78 40 34 } //01 00  L_cmsCreateMutex@4
		$a_01_2 = {4c 63 6d 73 42 75 69 6c 64 47 61 6d 6d 61 40 31 32 } //01 00  LcmsBuildGamma@12
		$a_01_3 = {4c 5f 63 6d 73 44 65 73 74 72 6f 79 4d 75 74 65 78 40 38 } //01 00  L_cmsDestroyMutex@8
		$a_01_4 = {4c 5f 63 6d 73 47 65 74 54 72 61 6e 73 66 6f 72 6d 55 73 65 72 44 61 74 61 40 34 } //01 00  L_cmsGetTransformUserData@4
		$a_01_5 = {4c 63 6d 73 41 64 61 70 74 54 6f 49 6c 6c 75 6d 69 6e 61 6e 74 40 31 36 } //01 00  LcmsAdaptToIlluminant@16
		$a_01_6 = {4c 63 6d 73 43 72 65 61 74 65 4c 61 62 34 50 72 6f 66 69 6c 65 54 48 52 40 38 } //01 00  LcmsCreateLab4ProfileTHR@8
		$a_01_7 = {4c 63 6d 73 44 65 73 61 74 75 72 61 74 65 4c 61 62 40 33 36 } //01 00  LcmsDesaturateLab@36
		$a_01_8 = {4c 63 6d 73 49 54 38 53 65 74 50 72 6f 70 65 72 74 79 55 6e 63 6f 6f 6b 65 64 40 31 32 } //01 00  LcmsIT8SetPropertyUncooked@12
		$a_01_9 = {4c 63 6d 73 78 79 59 32 58 59 5a 40 38 } //00 00  LcmsxyY2XYZ@8
	condition:
		any of ($a_*)
 
}