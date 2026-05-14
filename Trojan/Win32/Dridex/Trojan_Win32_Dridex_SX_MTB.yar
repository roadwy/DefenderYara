
rule Trojan_Win32_Dridex_SX_MTB{
	meta:
		description = "Trojan:Win32/Dridex.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 ff 21 7d fc 89 55 ec 8b 58 04 33 5d ec 8b 10 33 d6 83 65 f8 00 89 5d f4 8b 5d 08 89 55 f0 } //20
		$a_03_1 = {8b 0f 8b 45 0c 03 cb e8 ?? ?? ?? ?? 84 c0 75 ?? ff 45 08 8b 45 08 83 45 fc 02 83 c7 04 3b 46 14 72 de } //10
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}