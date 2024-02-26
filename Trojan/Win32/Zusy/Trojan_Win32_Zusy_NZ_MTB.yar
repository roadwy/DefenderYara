
rule Trojan_Win32_Zusy_NZ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {a3 60 c6 40 00 a1 90 01 04 a3 90 01 04 33 c0 a3 90 01 04 33 c0 a3 90 01 04 e8 90 01 04 ba 94 b0 40 00 8b c3 e8 b1 e8 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zusy_NZ_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {33 cc 4c b3 0a 81 aa 90 01 04 45 a8 93 fb 0c 67 13 4b 90 01 01 7e f3 ff b3 9f bb b9 b5 90 00 } //05 00 
		$a_01_1 = {31 cf 44 e2 23 86 f3 69 7d e2 a0 3d 7f 43 04 02 45 e6 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zusy_NZ_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {e8 6f fd ff ff 8b 4c 24 90 01 01 8b 54 24 08 85 c9 88 48 14 89 90 01 05 75 09 6a fd ff 15 2c 32 90 00 } //01 00 
		$a_01_1 = {70 00 72 00 6f 00 2e 00 70 00 61 00 72 00 74 00 72 00 69 00 61 00 2e 00 63 00 6f 00 6d 00 } //00 00  pro.partria.com
	condition:
		any of ($a_*)
 
}