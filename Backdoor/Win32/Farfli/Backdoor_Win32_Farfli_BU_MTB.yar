
rule Backdoor_Win32_Farfli_BU_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 01 34 9b 2c 65 88 01 41 4a 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}