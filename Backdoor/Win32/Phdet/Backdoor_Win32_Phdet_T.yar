
rule Backdoor_Win32_Phdet_T{
	meta:
		description = "Backdoor:Win32/Phdet.T,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d b7 00 00 00 0f 84 90 01 04 e8 90 01 04 89 85 90 01 02 ff ff 81 bd 90 01 02 ff ff 28 0a 00 00 74 90 01 01 81 bd 90 01 02 ff ff ce 0e 00 00 74 90 00 } //1
		$a_00_1 = {68 6f 45 59 4e 6a 01 e8 } //1
		$a_00_2 = {2d 6e 20 33 20 20 26 20 6d 6f 76 65 20 22 25 73 22 20 22 25 73 22 20 26 } //1 -n 3  & move "%s" "%s" &
		$a_03_3 = {83 78 04 04 74 90 01 01 81 bd 90 01 02 ff ff 70 17 00 00 0f 82 90 01 04 8b 85 90 01 02 ff ff 83 78 04 03 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}