
rule Trojan_UEFI_MosaicRegressor_A{
	meta:
		description = "Trojan:UEFI/MosaicRegressor.A,SIGNATURE_TYPE_PEHSTR,1c 00 1c 00 0b 00 00 "
		
	strings :
		$a_01_0 = {4e 74 66 73 50 6b 67 5c 4e 74 66 73 44 78 65 5c 6e 74 66 73 5c 62 6f 6f 74 73 65 63 74 2e 63 } //1 NtfsPkg\NtfsDxe\ntfs\bootsect.c
		$a_01_1 = {4e 74 66 73 50 6b 67 5c 4e 74 66 73 44 78 65 5c 4e 74 66 73 46 6c 75 73 68 2e 63 } //1 NtfsPkg\NtfsDxe\NtfsFlush.c
		$a_01_2 = {4e 74 66 73 50 6b 67 5c 4e 74 66 73 44 78 65 5c 4e 74 66 73 49 6e 66 6f 2e 63 } //1 NtfsPkg\NtfsDxe\NtfsInfo.c
		$a_01_3 = {4e 74 66 73 50 6b 67 5c 4e 74 66 73 44 78 65 5c 4e 74 66 73 53 65 74 50 6f 73 69 74 69 6f 6e 2e 63 } //1 NtfsPkg\NtfsDxe\NtfsSetPosition.c
		$a_01_4 = {4e 74 66 73 50 6b 67 5c 4e 74 66 73 44 78 65 5c 4e 74 66 73 47 65 74 50 6f 73 69 74 69 6f 6e 2e 63 } //1 NtfsPkg\NtfsDxe\NtfsGetPosition.c
		$a_01_5 = {4e 74 66 73 50 6b 67 5c 4e 74 66 73 44 78 65 5c 4e 74 66 73 57 72 69 74 65 2e 63 } //1 NtfsPkg\NtfsDxe\NtfsWrite.c
		$a_01_6 = {4e 74 66 73 50 6b 67 5c 4e 74 66 73 44 78 65 5c 4e 74 66 73 52 65 61 64 2e 63 } //1 NtfsPkg\NtfsDxe\NtfsRead.c
		$a_01_7 = {4e 74 66 73 50 6b 67 5c 4e 74 66 73 44 78 65 5c 4e 74 66 73 44 65 6c 65 74 65 2e 63 } //1 NtfsPkg\NtfsDxe\NtfsDelete.c
		$a_01_8 = {4e 74 66 73 50 6b 67 5c 4e 74 66 73 44 78 65 5c 4e 74 66 73 43 6c 6f 73 65 2e 63 } //1 NtfsPkg\NtfsDxe\NtfsClose.c
		$a_01_9 = {45 46 49 5f 45 52 52 4f 52 } //10 EFI_ERROR
		$a_01_10 = {64 65 76 69 63 65 20 69 73 20 64 69 72 74 79 2c 20 77 69 6c 6c 20 6e 6f 77 20 73 79 6e 63 5c 6e } //10 device is dirty, will now sync\n
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*10+(#a_01_10  & 1)*10) >=28
 
}