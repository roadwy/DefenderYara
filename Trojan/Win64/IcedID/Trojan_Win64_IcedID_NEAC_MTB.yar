
rule Trojan_Win64_IcedID_NEAC_MTB{
	meta:
		description = "Trojan:Win64/IcedID.NEAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {4c 03 c8 49 63 c4 41 83 c4 01 4c 03 c8 48 8b 44 24 28 4c 03 cb 43 0f b6 8c 31 ?? ?? ?? ?? 32 4c 07 ff 88 4c 37 ff 44 3b 64 24 20 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}