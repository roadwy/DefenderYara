
rule Backdoor_Win32_Farfli_BH_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 14 01 80 f2 19 80 c2 7a 88 14 01 41 3b ce 7c } //01 00 
		$a_01_1 = {8a 14 01 80 ea 7a 80 f2 19 88 14 01 41 3b ce 7c } //00 00 
	condition:
		any of ($a_*)
 
}