
rule Backdoor_Win32_Lotok_GNT_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c1 8a 4c 24 2c a3 90 01 04 8a 44 24 10 2a c1 89 35 90 01 04 32 c1 02 c1 8b 0d 90 01 04 0f af ca 89 0d 90 01 04 8b 4c 24 14 8b 54 24 1c 88 04 11 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}