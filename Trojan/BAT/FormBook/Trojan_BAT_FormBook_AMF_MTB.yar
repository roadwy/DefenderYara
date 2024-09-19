
rule Trojan_BAT_FormBook_AMF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 13 00 06 07 06 07 91 20 b5 03 00 00 59 d2 9c 07 17 58 0b 00 07 06 8e 69 fe 04 0d } //2
		$a_01_1 = {47 00 61 00 6d 00 65 00 2d 00 6f 00 66 00 2d 00 4c 00 69 00 66 00 65 00 } //1 Game-of-Life
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_FormBook_AMF_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 46 16 0d 2b 3a 16 13 04 2b 2c 11 07 07 09 58 08 11 04 58 6f ?? ?? ?? 0a 13 0b 12 0b 28 ?? ?? ?? 0a 13 09 11 06 11 05 11 09 9c 11 05 17 58 13 05 11 04 17 58 13 04 11 04 17 32 cf } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AMF_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 07 11 0c 11 06 11 0c 9a 1f 10 28 ?? ?? ?? 0a 9c 11 0c 17 58 } //2
		$a_01_1 = {4d 00 61 00 69 00 6e 00 50 00 6c 00 61 00 79 00 65 00 72 00 4d 00 61 00 6e 00 61 00 67 00 65 00 6d 00 65 00 6e 00 74 00 46 00 6f 00 72 00 6d 00 } //1 MainPlayerManagementForm
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_FormBook_AMF_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.AMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {5d 91 13 07 11 06 17 58 08 5d 13 08 07 11 06 91 11 07 61 13 09 07 11 08 91 13 0a 02 11 09 11 0a 28 ?? 00 00 06 13 0b 07 11 06 11 0b 28 ?? 00 00 0a 9c 00 11 06 17 58 } //2
		$a_01_1 = {45 00 6d 00 75 00 4c 00 69 00 73 00 74 00 65 00 72 00 } //1 EmuLister
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_FormBook_AMF_MTB_5{
	meta:
		description = "Trojan:BAT/FormBook.AMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {5d 91 0d 07 08 91 09 61 07 08 17 58 07 8e 69 5d 91 13 04 11 04 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 05 07 08 11 05 28 ?? 00 00 0a 9c 08 17 58 } //2
		$a_01_1 = {45 00 6d 00 70 00 6c 00 6f 00 79 00 65 00 65 00 49 00 6e 00 66 00 6f 00 41 00 70 00 70 00 } //1 EmployeeInfoApp
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_FormBook_AMF_MTB_6{
	meta:
		description = "Trojan:BAT/FormBook.AMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 16 09 a2 25 17 19 8d ?? 00 00 01 25 16 02 7b ?? 00 00 04 a2 25 17 02 7b ?? 00 00 04 a2 25 18 } //2
		$a_01_1 = {16 0c 2b 1a 00 07 08 18 5b 02 08 18 6f 6f 00 00 0a 1f 10 28 70 00 00 0a 9c 00 08 18 58 0c 08 06 fe 04 0d 09 2d de } //2
		$a_01_2 = {53 00 65 00 61 00 72 00 63 00 68 00 5f 00 49 00 6e 00 64 00 65 00 78 00 65 00 72 00 } //1 Search_Indexer
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}
rule Trojan_BAT_FormBook_AMF_MTB_7{
	meta:
		description = "Trojan:BAT/FormBook.AMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {11 04 2c 08 11 04 6f ?? ?? ?? 0a 00 dc 28 ?? ?? ?? 06 02 16 03 8e 69 6f ?? ?? ?? 0a 0b 07 28 ?? ?? ?? 0a 0c 08 6f ?? ?? ?? 0a 0d 09 16 9a 13 06 de 0b 06 2c 07 06 } //2
		$a_01_1 = {4d 00 6f 00 74 00 6f 00 72 00 53 00 69 00 6d 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 5c 00 4d 00 6f 00 74 00 6f 00 72 00 53 00 69 00 6d 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 5c 00 45 00 78 00 61 00 6d 00 70 00 6c 00 65 00 46 00 69 00 6c 00 65 00 2e 00 74 00 78 00 74 00 } //1 MotorSimulation\MotorSimulation\ExampleFile.txt
		$a_01_2 = {4c 00 6f 00 67 00 69 00 6e 00 20 00 53 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6c 00 } //1 Login Successful
		$a_01_3 = {4d 00 6f 00 74 00 6f 00 72 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Motor.Properties.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}