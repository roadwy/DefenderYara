
rule Backdoor_Win32_Farfli_BAD_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {33 ff 8b 45 08 8d 0c 02 0f b7 c7 8a 44 45 90 01 01 30 01 47 42 3b d6 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}