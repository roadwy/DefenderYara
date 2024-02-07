
rule Trojan_Win32_Zbot_BK_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {40 f7 d2 f7 d9 33 ce 03 d6 0f ba e1 08 72 01 } //01 00 
		$a_01_1 = {33 d5 4a 21 cb f7 d1 4b 2b ca 32 c4 03 ca 85 fe 74 05 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_3 = {67 65 74 68 6f 73 74 6e 61 6d 65 } //00 00  gethostname
	condition:
		any of ($a_*)
 
}