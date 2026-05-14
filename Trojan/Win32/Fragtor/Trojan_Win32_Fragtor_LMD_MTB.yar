
rule Trojan_Win32_Fragtor_LMD_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.LMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 14 31 80 c2 6d 80 f2 13 88 14 31 41 3b c8 } //20
		$a_01_1 = {8b ec 0f b6 45 10 99 b9 f9 1c 00 00 f7 f9 56 8b 75 0c 8d 4a 13 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}