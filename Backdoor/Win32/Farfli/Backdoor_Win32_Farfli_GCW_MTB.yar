
rule Backdoor_Win32_Farfli_GCW_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.GCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 09 8a d9 c0 e3 90 01 01 8b d0 c1 ea 90 01 01 32 d3 89 4d fc c1 e9 90 01 01 8a d8 c0 e3 90 01 01 32 cb 8a 5d 0c 81 45 90 01 01 47 86 c8 61 02 d1 8b 4d 10 83 e6 90 01 01 33 75 f8 32 d8 8a 0c b1 32 4d fc 02 cb 32 d1 28 17 ff 4d f4 0f b6 07 0f 85 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}