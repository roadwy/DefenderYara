
rule Worm_Win32_Vobfus_gen_J{
	meta:
		description = "Worm:Win32/Vobfus.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {ee 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 } //5
		$a_03_1 = {8b d0 8d 4d d0 ff 15 ?? ?? ?? ?? 50 8b 4d dc ff 15 ?? ?? ?? ?? 50 6a ff 68 20 01 00 00 ff 15 90 09 1a 00 c7 45 fc ?? 00 00 00 c7 45 dc ?? 00 00 00 c7 45 fc ?? 00 00 00 e8 } //5
		$a_03_2 = {68 00 00 00 40 6a 00 ff 15 ?? ?? 40 00 ff 15 ?? ?? 40 00 90 0a 38 00 0f bf ?? dc 89 [0-05] db [0-05] dd ?? ?? ff ff ff 8b ?? ?? ff ff ff ?? 8b ?? ?? ff ff ff } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5) >=15
 
}