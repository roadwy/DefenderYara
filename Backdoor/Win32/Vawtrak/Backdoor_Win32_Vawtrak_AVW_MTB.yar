
rule Backdoor_Win32_Vawtrak_AVW_MTB{
	meta:
		description = "Backdoor:Win32/Vawtrak.AVW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a c7 83 f2 06 0f 8d ?? ?? ?? ?? 5d 00 59 ff d5 69 d3 d2 ff eb 23 ec 28 00 65 00 00 81 ad ?? ?? ?? ?? ?? ?? ?? ?? e0 23 d6 03 03 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}