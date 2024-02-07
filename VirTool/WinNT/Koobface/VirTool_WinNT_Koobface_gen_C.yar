
rule VirTool_WinNT_Koobface_gen_C{
	meta:
		description = "VirTool:WinNT/Koobface.gen!C,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 6f 41 74 74 61 63 68 44 65 76 69 63 65 54 6f 44 65 76 69 63 65 53 74 61 63 6b } //01 00  IoAttachDeviceToDeviceStack
		$a_01_1 = {4b 66 52 65 6c 65 61 73 65 53 70 69 6e 4c 6f 63 6b } //01 00  KfReleaseSpinLock
		$a_01_2 = {49 6f 66 43 6f 6d 70 6c 65 74 65 52 65 71 75 65 73 74 } //01 00  IofCompleteRequest
		$a_01_3 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 54 00 63 00 70 00 } //01 00  \Device\Tcp
		$a_01_4 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 50 00 6f 00 64 00 6d 00 65 00 6e 00 61 00 46 00 44 00 } //00 00  \Device\PodmenaFD
	condition:
		any of ($a_*)
 
}