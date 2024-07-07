
rule Trojan_Win32_KillMBR_BD_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 42 52 20 77 61 73 20 73 75 63 63 65 73 73 66 75 6c 79 20 65 72 61 73 65 64 } //2 MBR was successfuly erased
		$a_01_1 = {4d 69 6e 65 48 61 63 6b } //2 MineHack
		$a_01_2 = {55 73 65 72 73 5c 4d 6f 72 73 69 6b } //2 Users\Morsik
		$a_01_3 = {53 6f 6d 65 74 68 69 6e 67 20 68 61 73 20 67 6f 6e 65 20 77 72 6f 6e 67 21 } //2 Something has gone wrong!
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}