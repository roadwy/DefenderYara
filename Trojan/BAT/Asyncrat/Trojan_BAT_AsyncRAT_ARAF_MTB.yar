
rule Trojan_BAT_AsyncRAT_ARAF_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 73 79 6e 63 43 6c 69 65 6e 74 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //2 AsyncClient.g.resources
		$a_80_1 = {53 74 75 62 2e 65 78 65 } //Stub.exe  2
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_5 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}