
rule Backdoor_Win32_Farfli_BI_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {33 d1 03 c2 8b 55 e0 33 55 f8 8b 4d d4 83 e1 03 33 4d bc 8b 75 10 8b 0c 8e 33 4d ec 03 d1 33 c2 8b 55 08 0f b6 0a 2b c8 8b 55 08 88 0a } //00 00 
	condition:
		any of ($a_*)
 
}