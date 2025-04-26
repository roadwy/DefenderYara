
rule Backdoor_Win32_Tofsee_KAD_MTB{
	meta:
		description = "Backdoor:Win32/Tofsee.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {14 83 f8 01 75 01 cc 83 7d ac 00 75 40 e8 5e 9e fe ff c7 00 16 00 00 00 6a 00 68 eb } //3
		$a_01_1 = {01 cc 83 7d b0 00 75 40 e8 d3 9e fe ff c7 00 16 00 00 00 6a 00 68 ea 01 00 00 68 30 42 41 } //4
		$a_01_2 = {7d fc 00 74 21 8b 55 18 f7 da 1a d2 80 e2 e0 80 c2 70 8b 45 fc 88 10 8b 4d fc 83 c1 } //5
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*4+(#a_01_2  & 1)*5) >=12
 
}