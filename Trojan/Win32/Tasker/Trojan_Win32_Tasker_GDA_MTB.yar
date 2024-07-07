
rule Trojan_Win32_Tasker_GDA_MTB{
	meta:
		description = "Trojan:Win32/Tasker.GDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 4c 24 13 8b 4c 24 18 80 64 24 10 2e c6 44 24 10 4e 81 6c 24 10 65 55 a3 0d 31 74 24 10 c7 44 24 10 c0 79 43 59 33 74 24 10 23 74 24 10 0f 90 44 24 10 0f 9c 44 24 10 66 3b 74 24 11 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}