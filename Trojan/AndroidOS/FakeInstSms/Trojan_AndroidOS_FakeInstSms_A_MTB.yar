
rule Trojan_AndroidOS_FakeInstSms_A_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {46 40 36 30 46 05 f0 39 fb a5 63 44 34 20 46 05 f0 44 fb 30 46 05 f0 39 fb 3c e0 25 46 40 35 28 46 05 f0 2b fb 20 6a 00 28 01 d0 05 f0 3e fb e0 6f 20 62 00 28 11 d0 e1 69 22 46 60 32 6b 46 1a 60 02 22 00 23 05 f0 39 fb 07 e0 25 46 40 35 28 46 05 f0 13 fb 80 20 20 58 60 62 44 34 20 46 05 f0 1c fb 28 46 05 f0 11 fb 14 e0 44 34 20 46 05 f0 14 fb 0f e0 20 69 e1 68 09 6a 05 f0 26 fb 20 69 03 a9 05 f0 2a fb 20 69 02 a9 05 f0 2e fb 01 e0 01 20 } //01 00 
		$a_01_1 = {41 63 74 69 76 61 74 69 6e 67 20 44 65 78 4c 6f 61 64 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}