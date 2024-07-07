
rule Trojan_Win64_Dridex_GXZ_MTB{
	meta:
		description = "Trojan:Win64/Dridex.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 89 f0 4d 0f af c0 4d 01 d9 4d 01 c1 8b 4d cc d3 e8 89 45 24 48 8b 4d a0 4c 8b 45 d0 49 d3 e8 4c 8b 55 18 4c 89 45 10 49 01 f2 81 f2 7c 71 00 00 4d 0f af d2 89 55 ec 8b 45 cc 2d 90 01 04 8b 55 04 89 45 24 89 55 0c 4d 39 d1 0f 85 90 00 } //10
		$a_01_1 = {40 2e 75 63 6c 67 74 66 } //1 @.uclgtf
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}