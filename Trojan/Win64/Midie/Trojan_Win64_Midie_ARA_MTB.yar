
rule Trojan_Win64_Midie_ARA_MTB{
	meta:
		description = "Trojan:Win64/Midie.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 cb 80 e1 03 c0 e1 03 41 b9 73 5d 2b 6b 41 d3 e9 44 32 4c 1c 30 0f be c3 6b c8 37 44 32 c9 49 3b d0 73 20 48 8d 42 01 48 89 45 40 48 8d 45 30 49 83 f8 0f 48 0f 47 45 30 44 88 0c 10 c6 44 10 01 00 eb 09 } //5
		$a_80_1 = {73 63 20 73 74 6f 70 20 41 41 } //sc stop AA  5
		$a_80_2 = {5c 53 79 73 6d 6f 6e 5f 44 72 76 2e 73 79 73 } //\Sysmon_Drv.sys  2
	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*2) >=7
 
}