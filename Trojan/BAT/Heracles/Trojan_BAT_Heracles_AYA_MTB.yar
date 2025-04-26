
rule Trojan_BAT_Heracles_AYA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 79 70 61 73 73 45 54 57 2e 70 64 62 } //2 BypassETW.pdb
		$a_01_1 = {24 36 39 31 65 32 38 61 34 2d 32 63 36 66 2d 34 66 38 31 2d 62 38 37 63 2d 37 37 33 64 63 35 64 30 34 33 34 62 } //1 $691e28a4-2c6f-4f81-b87c-773dc5d0434b
		$a_01_2 = {53 74 61 72 74 50 61 74 63 68 } //1 StartPatch
		$a_01_3 = {4d 65 6d 6f 72 79 50 61 74 63 68 } //1 MemoryPatch
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}