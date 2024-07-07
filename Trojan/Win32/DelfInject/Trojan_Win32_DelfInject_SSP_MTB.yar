
rule Trojan_Win32_DelfInject_SSP_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.SSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 66 46 30 69 75 77 45 64 74 47 36 4f 73 63 4b 4d 76 2e 54 6b 64 6e 34 79 52 63 63 6a 75 44 4d 71 64 56 6d 4a } //2 CfF0iuwEdtG6OscKMv.Tkdn4yRccjuDMqdVmJ
		$a_01_1 = {46 4a 43 58 54 5a 62 59 78 } //2 FJCXTZbYx
		$a_01_2 = {38 38 39 2e 31 31 34 2e 31 2e 31 34 34 35 31 } //2 889.114.1.14451
		$a_01_3 = {24 38 63 62 35 36 65 36 34 2d 38 38 33 36 2d 34 32 33 30 2d 62 61 33 31 2d 36 31 61 65 31 62 33 39 64 31 36 63 } //1 $8cb56e64-8836-4230-ba31-61ae1b39d16c
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=2
 
}