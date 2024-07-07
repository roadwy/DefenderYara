
rule Backdoor_Win32_Farfli_GMQ_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.GMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 31 d2 f7 f6 0f b6 04 17 30 04 0b 83 c1 01 39 cd 75 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}