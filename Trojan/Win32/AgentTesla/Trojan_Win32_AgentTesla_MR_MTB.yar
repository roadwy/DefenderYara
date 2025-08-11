
rule Trojan_Win32_AgentTesla_MR_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {36 34 36 39 36 44 36 54 36 59 36 5f 36 64 36 6a 36 6f 36 75 36 7a } //15 64696D6T6Y6_6d6j6o6u6z
		$a_01_1 = {39 1e 39 25 39 33 39 39 39 3f 39 4a 39 59 39 68 39 6d 39 73 39 78 39 } //5
		$a_03_2 = {31 6f 31 a8 31 b4 31 ba ?? ?? ?? ?? 31 ed 31 f3 31 02 32 44 32 52 32 63 32 } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*5+(#a_03_2  & 1)*10) >=30
 
}