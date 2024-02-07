
rule Trojan_Win32_Emotet_DBY_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 04 00 "
		
	strings :
		$a_02_0 = {33 d2 f7 f1 8b 44 24 90 01 01 8a 0c 50 8b 44 24 90 01 01 30 08 ff 44 24 90 01 01 8b 44 24 90 01 01 3b 44 24 90 01 01 0f 85 90 00 } //01 00 
		$a_00_1 = {4d 00 71 00 5a 00 6c 00 7a 00 67 00 30 00 47 00 75 00 67 00 7a 00 67 00 6c 00 71 00 30 00 56 00 46 00 64 00 4b 00 30 00 33 00 71 00 31 00 66 00 4a 00 58 00 6e 00 57 00 57 00 } //01 00  MqZlzg0Gugzglq0VFdK03q1fJXnWW
		$a_81_2 = {43 72 79 70 74 53 74 72 69 6e 67 54 6f 42 69 6e 61 72 79 41 } //01 00  CryptStringToBinaryA
		$a_81_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } //01 00  VirtualAllocExNuma
		$a_81_4 = {6d 65 6d 63 70 79 } //00 00  memcpy
	condition:
		any of ($a_*)
 
}