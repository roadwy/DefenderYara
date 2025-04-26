
rule TrojanDropper_Win32_Pibus_A_drv{
	meta:
		description = "TrojanDropper:Win32/Pibus.A!drv,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 06 00 00 "
		
	strings :
		$a_03_0 = {fa 0f 20 c0 89 44 24 08 25 ff ff fe ff 0f 22 c0 33 ff a1 ?? ?? ?? ?? 8b 00 8b 0c b8 8b 44 24 10 8d 34 b8 8b 06 } //10
		$a_00_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 49 00 70 00 66 00 69 00 6c 00 74 00 65 00 72 00 64 00 72 00 69 00 76 00 65 00 72 00 } //10 \Device\Ipfilterdriver
		$a_00_2 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //10 KeServiceDescriptorTable
		$a_00_3 = {5c 64 72 69 76 65 72 2e 70 64 62 } //1 \driver.pdb
		$a_00_4 = {68 6f 6f 6b 69 6e 67 2e 63 70 70 3a 20 53 53 54 20 69 6e 64 65 78 } //1 hooking.cpp: SST index
		$a_00_5 = {42 00 6f 00 67 00 75 00 73 00 50 00 72 00 6f 00 74 00 6f 00 63 00 6f 00 6c 00 } //1 BogusProtocol
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=31
 
}