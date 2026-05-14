
rule Trojan_Win32_Phorpiex_ABP_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.ABP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {ba 68 00 00 00 66 89 95 20 f9 ff ff b8 74 00 00 00 66 89 85 22 f9 ff ff b9 74 00 00 00 66 89 8d 24 f9 ff ff ba 70 00 00 00 66 89 95 26 f9 ff ff b8 3a 00 00 00 66 89 85 28 f9 ff ff b9 2f 00 00 00 66 89 8d 2a f9 ff ff ba 2f 00 00 00 66 89 95 2c f9 ff ff b8 31 00 00 00 66 89 85 2e f9 ff ff b9 37 00 00 00 66 89 8d 30 f9 ff ff ba 38 00 00 00 66 89 95 32 f9 ff ff b8 2e 00 00 00 66 89 85 34 f9 ff ff b9 31 00 00 00 66 89 8d 36 f9 ff ff ba 36 00 00 00 66 89 95 38 f9 ff ff b8 2e 00 00 00 66 89 85 3a f9 ff ff b9 35 00 00 00 66 89 8d 3c f9 ff ff ba 34 00 00 00 66 89 95 3e f9 ff ff b8 2e 00 00 00 66 89 85 40 f9 ff ff b9 31 00 00 00 66 89 8d 42 f9 ff ff ba 30 00 00 00 66 89 95 44 f9 ff ff b8 39 00 00 00 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}