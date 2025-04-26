
rule Trojan_Win32_Xnet_ARAZ_MTB{
	meta:
		description = "Trojan:Win32/Xnet.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 8b 45 08 01 c2 8b 4d fc 8b 45 08 01 c8 0f b6 00 32 45 ec 88 02 83 45 fc 01 8b 45 fc 3b 45 0c 7c dc } //10
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}