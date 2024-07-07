
rule Backdoor_Win32_Farfli_AAB_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.AAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d fc 80 04 11 7a 03 ca 8b 4d fc 80 34 11 19 03 ca 42 3b d0 7c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}