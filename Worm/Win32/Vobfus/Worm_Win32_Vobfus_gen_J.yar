
rule Worm_Win32_Vobfus_gen_J{
	meta:
		description = "Worm:Win32/Vobfus.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {ee 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 } //5
		$a_03_1 = {8b d0 8d 4d d0 ff 15 90 01 04 50 8b 4d dc ff 15 90 01 04 50 6a ff 68 20 01 00 00 ff 15 90 09 1a 00 c7 45 fc 90 01 01 00 00 00 c7 45 dc 90 01 01 00 00 00 c7 45 fc 90 01 01 00 00 00 e8 90 00 } //5
		$a_03_2 = {68 00 00 00 40 6a 00 ff 15 90 01 02 40 00 ff 15 90 01 02 40 00 90 0a 38 00 0f bf 90 01 01 dc 89 90 02 05 db 90 02 05 dd 90 01 02 ff ff ff 8b 90 01 02 ff ff ff 90 01 01 8b 90 01 02 ff ff ff 90 00 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5) >=15
 
}