
rule Trojan_Win32_Bobik_KK_MTB{
	meta:
		description = "Trojan:Win32/Bobik.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 43 0c ff 75 ec 8b 40 0c ff d0 83 f8 64 8b 43 0c } //20
		$a_01_1 = {8b 40 10 6a 00 ff 75 ec ff d0 8b 4b 0c 8b f0 6a 01 ff 75 ec 8b 49 10 ff d1 89 45 f0 85 f6 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}