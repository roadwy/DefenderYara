
rule Trojan_Win64_DriverLoader_RDB_MTB{
	meta:
		description = "Trojan:Win64/DriverLoader.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {79 6f 75 20 6d 75 73 74 20 64 69 73 61 62 6c 65 20 76 75 6c 6e 65 72 61 62 6c 65 20 64 72 69 76 65 72 20 6c 69 73 74 20 74 6f 20 75 73 65 20 6b 64 6d 61 70 70 65 72 20 77 69 74 68 20 69 6e 74 65 6c 20 64 72 69 76 65 72 } //2 you must disable vulnerable driver list to use kdmapper with intel driver
		$a_01_1 = {59 6f 75 72 20 76 75 6c 6e 65 72 61 62 6c 65 20 64 72 69 76 65 72 20 6c 69 73 74 20 69 73 20 65 6e 61 62 6c 65 64 20 61 6e 64 20 68 61 76 65 20 62 6c 6f 63 6b 65 64 20 74 68 65 20 64 72 69 76 65 72 20 6c 6f 61 64 69 6e 67 } //2 Your vulnerable driver list is enabled and have blocked the driver loading
		$a_01_2 = {50 72 6f 62 61 62 6c 79 20 73 6f 6d 65 20 61 6e 74 69 63 68 65 61 74 20 6f 72 20 61 6e 74 69 76 69 72 75 73 20 72 75 6e 6e 69 6e 67 20 62 6c 6f 63 6b 69 6e 67 20 74 68 65 20 6c 6f 61 64 20 6f 66 20 76 75 6c 6e 65 72 61 62 6c 65 20 64 72 69 76 65 72 } //1 Probably some anticheat or antivirus running blocking the load of vulnerable driver
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}