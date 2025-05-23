
rule Trojan_BAT_AgentTesla_JVH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JVH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_81_0 = {44 61 74 61 44 69 72 65 63 74 6f 72 79 7c 5c 62 69 6e 5c 44 65 62 75 67 5c 50 61 79 72 6f 6c 6c 4d 61 6e 61 67 65 72 44 42 2e 6d 64 66 } //10 DataDirectory|\bin\Debug\PayrollManagerDB.mdf
		$a_81_1 = {24 63 30 30 36 37 64 65 65 2d 32 37 63 61 2d 34 36 61 63 2d 61 66 64 33 2d 36 30 37 61 63 66 38 65 39 35 31 36 } //2 $c0067dee-27ca-46ac-afd3-607acf8e9516
		$a_81_2 = {24 36 32 37 35 32 37 61 38 2d 32 61 65 38 2d 34 39 63 35 2d 39 62 65 31 2d 35 36 30 63 32 35 61 61 39 35 33 32 } //2 $627527a8-2ae8-49c5-9be1-560c25aa9532
		$a_81_3 = {24 65 33 64 39 36 33 33 66 2d 31 36 65 61 2d 34 33 64 65 2d 61 30 30 63 2d 38 66 30 31 64 64 32 39 64 30 34 39 } //2 $e3d9633f-16ea-43de-a00c-8f01dd29d049
		$a_81_4 = {53 6a 33 31 50 6e 69 30 4b 46 6b 36 39 41 72 73 38 59 37 58 71 } //1 Sj31Pni0KFk69Ars8Y7Xq
		$a_81_5 = {50 61 79 72 6f 6c 6c 20 4d 61 6e 61 67 65 72 } //1 Payroll Manager
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=13
 
}