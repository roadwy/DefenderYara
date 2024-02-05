
rule Trojan_Win32_LockbitCrypt_SB_MTB{
	meta:
		description = "Trojan:Win32/LockbitCrypt.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 49 00 6a 00 6a 00 6a 00 ff d6 83 ef 01 c7 05 90 01 04 00 00 00 00 75 90 09 0d 00 56 8b 35 90 01 04 57 bf 90 00 } //01 00 
		$a_03_1 = {33 f6 81 fe 90 01 04 75 90 01 01 81 05 90 01 08 68 90 01 04 68 90 01 04 ff d7 81 3d 90 01 08 0f 84 90 01 04 46 81 fe 90 01 04 7c 90 00 } //01 00 
		$a_01_2 = {51 6a 40 50 52 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}