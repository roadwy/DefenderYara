
rule Backdoor_Win32_Farfli_BO_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8a 14 01 80 ea 31 80 f2 fc 88 14 01 41 3b ce 7c } //00 00 
	condition:
		any of ($a_*)
 
}