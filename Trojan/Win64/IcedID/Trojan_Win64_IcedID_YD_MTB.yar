
rule Trojan_Win64_IcedID_YD_MTB{
	meta:
		description = "Trojan:Win64/IcedID.YD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 02 43 32 04 31 41 ?? ?? ?? 49 ?? ?? 8b 02 d3 c8 ff c0 89 02 83 e0 ?? 0f b6 c8 41 ?? ?? d3 c8 ff c0 41 ?? ?? 48 ?? ?? ?? ?? 4c ?? ?? ?? ?? 73 } //1
		$a_00_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}