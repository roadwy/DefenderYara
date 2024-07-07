
rule Worm_Win32_Rootcip_A{
	meta:
		description = "Worm:Win32/Rootcip.A,SIGNATURE_TYPE_PEHSTR,29 00 29 00 09 00 00 "
		
	strings :
		$a_01_0 = {5c 68 61 63 6b 5f 64 61 5f 69 70 64 } //10 \hack_da_ipd
		$a_01_1 = {5c 53 59 53 54 45 4d 33 32 5c 5f 74 64 69 73 65 72 76 5f 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //10 \SYSTEM32\_tdiserv_\svchost.exe
		$a_01_2 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //10 ZwQuerySystemInformation
		$a_01_3 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //10 KeServiceDescriptorTable
		$a_01_4 = {5f 74 64 69 73 65 72 76 5f 48 4f 4f 4b } //1 _tdiserv_HOOK
		$a_01_5 = {5f 74 64 69 70 61 63 6b 65 74 5f 48 4f 4f 4b } //1 _tdipacket_HOOK
		$a_01_6 = {5c 54 64 69 55 70 64 61 74 65 2e 73 79 73 } //1 \TdiUpdate.sys
		$a_01_7 = {54 64 69 48 6f 6f 6b 20 55 70 64 61 74 65 20 44 72 69 76 65 72 } //1 TdiHook Update Driver
		$a_01_8 = {5c 5c 2e 5c 54 64 69 54 72 61 6e 73 66 65 72 43 6c 69 65 6e 74 } //1 \\.\TdiTransferClient
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=41
 
}