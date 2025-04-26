
rule Backdoor_Win32_Telemot_D{
	meta:
		description = "Backdoor:Win32/Telemot.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {75 28 83 bd ?? ?? ff ff 40 73 1f 8b 95 ?? ?? ff ff 8b 45 0c 89 84 95 ?? ?? ff ff 8b 8d 90 1b 00 ff ff 83 c1 01 89 8d 90 1b 00 ff ff 33 d2 85 d2 } //2
		$a_01_1 = {66 69 72 65 77 61 6c 6c 00 00 00 00 72 65 67 00 73 63 72 65 65 6e 73 68 6f 74 00 00 75 6e 69 6e 73 74 61 6c 6c 00 00 00 75 70 64 61 74 65 } //1
		$a_01_2 = {4c 6f 67 69 63 61 6c 20 44 69 73 6b 20 4d 61 6e 61 67 65 72 20 55 73 65 72 73 20 53 65 72 76 69 63 65 00 00 43 48 4b 44 53 4b 33 32 } //1
		$a_01_3 = {62 61 6e 20 3c 61 64 64 2f 64 65 6c 2f 73 68 6f 77 3e 20 5b 49 50 5d 20 5b 6d 73 67 5d } //1 ban <add/del/show> [IP] [msg]
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}