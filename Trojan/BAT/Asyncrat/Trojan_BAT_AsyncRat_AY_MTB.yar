
rule Trojan_BAT_AsyncRat_AY_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 2b 30 08 09 a3 4b 00 00 01 13 04 28 90 01 03 06 11 04 07 6f 90 01 03 0a 28 90 01 03 06 6f 90 01 03 0a 2c 05 dd c9 00 00 00 de 03 26 de 00 09 17 58 0d 09 08 8e 69 32 ca 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AsyncRat_AY_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {56 69 72 74 75 61 6c 4d 61 63 68 69 6e 65 44 65 74 65 63 74 6f 72 } //2 VirtualMachineDetector
		$a_01_1 = {49 6e 73 74 61 6c 6c 61 74 69 6f 6e 43 6c 61 73 73 } //2 InstallationClass
		$a_01_2 = {45 6e 63 72 79 70 74 69 6f 6e 43 6c 61 73 73 } //2 EncryptionClass
		$a_01_3 = {46 61 6b 65 4d 65 73 73 61 67 65 43 6c 61 73 73 } //2 FakeMessageClass
		$a_01_4 = {5a 6f 6e 65 49 64 65 6e 74 69 66 69 65 72 43 6c 61 73 73 } //2 ZoneIdentifierClass
		$a_01_5 = {49 57 73 68 52 75 6e 74 69 6d 65 4c 69 62 72 61 72 79 } //2 IWshRuntimeLibrary
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}