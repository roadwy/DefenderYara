
rule Trojan_Win32_Vidar_EH_MTB{
	meta:
		description = "Trojan:Win32/Vidar.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 45 50 4e 72 49 6f 46 58 6d 7a } //1 AEPNrIoFXmz
		$a_01_1 = {4c 54 46 66 4c 62 43 50 6f 75 56 } //1 LTFfLbCPouV
		$a_01_2 = {4c 48 68 44 42 42 6a 69 6a 4e 4f 74 68 } //1 LHhDBBjijNOth
		$a_01_3 = {72 50 45 75 50 75 69 67 58 6e 53 67 72 76 4d 71 48 6e } //1 rPEuPuigXnSgrvMqHn
		$a_01_4 = {45 48 46 70 50 56 4a 63 45 79 68 6a 78 68 55 56 45 4b 6e 68 63 6c 47 46 44 51 41 4c 4e 48 48 49 74 4f 7a } //1 EHFpPVJcEyhjxhUVEKnhclGFDQALNHHItOz
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}