
rule Trojan_Win32_IceID_SK_MTB{
	meta:
		description = "Trojan:Win32/IceID.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5a 51 74 76 7a 50 57 55 59 6e 6f 42 52 47 } //1 ZQtvzPWUYnoBRG
		$a_01_1 = {7a 45 70 6c 51 46 6d 4e 50 66 62 6f 41 74 68 4a } //1 zEplQFmNPfboAthJ
		$a_01_2 = {53 54 72 73 56 6d 76 42 54 6a 44 67 42 59 46 } //1 STrsVmvBTjDgBYF
		$a_01_3 = {75 61 73 69 66 62 79 75 67 61 73 68 66 6a 61 6b 73 68 62 61 73 73 } //1 uasifbyugashfjakshbass
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}