
rule TrojanDropper_Win32_Swrort_ASW_MTB{
	meta:
		description = "TrojanDropper:Win32/Swrort.ASW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 45 fc c7 44 24 ?? ?? ?? ?? ?? 8b 45 fc 89 04 24 e8 2b 06 00 00 83 ec 08 c7 45 f8 ?? ?? ?? ?? c7 44 24 04 } //1
		$a_01_1 = {8b 45 f8 89 44 24 08 c7 44 24 04 ec 79 49 00 8b 45 f4 89 04 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}