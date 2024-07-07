
rule Trojan_Win32_NSISInject_RA_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 9d b8 f4 ff ff 0f af 9d 0c f5 ff ff 8b 45 14 8b 08 03 8d 18 f5 ff ff 0f be 71 04 03 de 0f be 95 10 f5 ff ff 2b da 89 9d b8 f4 ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_NSISInject_RA_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 40 89 45 f4 8b 45 f4 3b 45 e0 73 25 8b 45 f4 99 6a 0c 59 f7 f9 8b 45 e4 0f b6 04 10 8b 4d dc 03 4d f4 0f b6 09 33 c8 8b 45 dc 03 45 f4 88 08 eb cc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_NSISInject_RA_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4e 00 6f 00 6e 00 72 00 65 00 67 00 61 00 72 00 64 00 61 00 6e 00 63 00 65 00 } //1 Software\Nonregardance
		$a_01_1 = {54 00 72 00 6f 00 75 00 70 00 69 00 61 00 6c 00 73 00 5c 00 41 00 67 00 67 00 72 00 65 00 73 00 73 00 69 00 76 00 65 00 2e 00 69 00 6e 00 69 00 } //1 Troupials\Aggressive.ini
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 52 00 65 00 63 00 72 00 65 00 61 00 6e 00 63 00 79 00 } //1 Software\Recreancy
		$a_01_3 = {46 00 6f 00 72 00 69 00 76 00 72 00 65 00 64 00 65 00 73 00 5c 00 52 00 69 00 67 00 74 00 69 00 67 00 74 00 6e 00 6f 00 6b 00 2e 00 64 00 6c 00 6c 00 } //1 Forivredes\Rigtigtnok.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}