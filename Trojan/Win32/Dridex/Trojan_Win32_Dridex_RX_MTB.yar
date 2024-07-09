
rule Trojan_Win32_Dridex_RX_MTB{
	meta:
		description = "Trojan:Win32/Dridex.RX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 c7 30 50 07 01 [0-05] 89 3d ?? ?? ?? ?? [0-0a] 89 39 [0-2f] 74 } //1
		$a_03_1 = {81 c2 14 c8 08 01 89 16 83 c6 04 83 6c 24 10 01 66 89 0d [0-1f] 75 90 0a 3f 00 8d 4c 01 bf [0-0f] 69 c9 ?? ?? ?? ?? 0f af d7 69 d2 90 1b 03 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}