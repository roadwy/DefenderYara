
rule Backdoor_Win32_Farfli_FT_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.FT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 74 24 0c 80 c2 08 85 f6 76 10 8b 44 24 08 8a 08 32 ca 02 ca 88 08 40 4e 75 f4 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}