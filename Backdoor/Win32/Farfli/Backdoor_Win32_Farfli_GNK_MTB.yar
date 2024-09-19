
rule Backdoor_Win32_Farfli_GNK_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.GNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 02 99 be c8 01 00 00 f7 fe 83 c2 36 8b 45 e0 8b 40 08 8b 75 ec 0f be 04 30 33 c2 8b 55 ec 88 04 11 8b 45 e8 83 c0 01 89 45 e8 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}