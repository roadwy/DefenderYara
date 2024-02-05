
rule Backdoor_Win32_Farfli_AAC_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.AAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8a 14 01 80 f2 19 80 c2 46 88 14 01 41 3b 4c 24 08 7c } //00 00 
	condition:
		any of ($a_*)
 
}