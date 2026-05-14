
rule Trojan_Win64_LummaStealer_AHC_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 87 db 48 8d 1b 90 4d 8d 12 90 4d 87 d2 90 e9 } //30
		$a_01_1 = {41 5a 48 89 c9 4d 89 c0 4d 89 c9 41 51 4d 87 c9 41 59 } //20
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}
rule Trojan_Win64_LummaStealer_AHC_MTB_2{
	meta:
		description = "Trojan:Win64/LummaStealer.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 f7 e9 48 01 ca 48 d1 fa 48 89 cb 48 c1 f9 3f 48 29 ca 48 85 d2 0f 8e ?? ?? ?? ?? 48 8b 44 24 68 48 89 d1 48 89 c6 } //10
		$a_01_1 = {48 8b 44 24 70 48 89 c2 48 89 d7 48 99 48 f7 f9 48 83 f8 01 75 } //20
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*20) >=30
 
}