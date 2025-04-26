
rule Trojan_BAT_Bladabindi_MBIO_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.MBIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 15 a2 09 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 56 00 00 00 0d 00 00 00 16 00 00 00 41 00 00 00 35 00 00 00 92 } //1
		$a_01_1 = {24 62 35 35 64 34 65 62 30 2d 63 64 36 61 2d 34 63 32 35 2d 38 34 33 33 2d 61 38 62 31 35 62 39 30 36 38 33 30 } //1 $b55d4eb0-cd6a-4c25-8433-a8b15b906830
		$a_01_2 = {57 69 6e 64 6f 77 73 41 70 70 6c 69 63 61 74 69 6f 6e 32 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 WindowsApplication2.Resources.resource
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}