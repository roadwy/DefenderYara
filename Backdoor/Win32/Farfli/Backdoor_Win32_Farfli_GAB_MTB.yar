
rule Backdoor_Win32_Farfli_GAB_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.GAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 db 57 33 c0 be 00 ?? ?? ?? 80 b0 ?? ?? ?? ?? b6 40 3b c6 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}