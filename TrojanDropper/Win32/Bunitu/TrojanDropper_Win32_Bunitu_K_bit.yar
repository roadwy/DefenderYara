
rule TrojanDropper_Win32_Bunitu_K_bit{
	meta:
		description = "TrojanDropper:Win32/Bunitu.K!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 8b c8 8b 41 3c 8b 54 08 78 03 d1 8b 52 1c 8b 14 11 01 14 24 c3 } //1
		$a_03_1 = {8b fa b9 2c 01 00 00 f2 ae 5a 57 c6 47 ff 90 03 01 04 22 21 fe 47 ff b0 90 02 10 83 c7 01 8d 35 90 01 04 b9 06 00 00 00 90 00 } //2
		$a_03_2 = {03 c6 03 c0 8d 0c 32 81 c1 90 01 04 83 ea 90 01 01 2b d1 87 ca 81 e9 90 01 04 2b f9 81 fe 90 00 } //2
		$a_01_3 = {61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 72 75 6c 65 20 6e 61 6d 65 3d 22 52 75 6e 64 6c 6c 33 32 22 20 64 69 72 3d 69 6e 20 61 63 74 69 6f 6e 3d 61 6c 6c 6f 77 20 70 72 6f 74 6f 63 6f 6c 3d 61 6e 79 20 70 72 6f 67 72 61 6d 3d } //1 advfirewall firewall add rule name="Rundll32" dir=in action=allow protocol=any program=
		$a_01_4 = {53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 53 65 72 76 69 63 65 73 5c 4d 42 41 4d 50 72 6f 74 65 63 74 6f 72 } //1 SYSTEM\ControlSet001\Services\MBAMProtector
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}