
rule Trojan_Win32_Redcap_GNZ_MTB{
	meta:
		description = "Trojan:Win32/Redcap.GNZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {32 0a 16 84 c6 5f 1d ?? ?? ?? ?? 31 1b e0 } //5
		$a_01_1 = {b1 6c 82 32 ae b4 39 e5 04 3b 20 38 c2 } //5
		$a_01_2 = {4d 79 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 MyUnregisterServer
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}