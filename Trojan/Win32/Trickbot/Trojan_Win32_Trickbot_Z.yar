
rule Trojan_Win32_Trickbot_Z{
	meta:
		description = "Trojan:Win32/Trickbot.Z,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 67 65 74 71 2f } //1 /getq/
		$a_01_1 = {6a 5c 89 3e e8 76 02 00 00 8a d0 57 6a 47 88 55 ff 88 56 04 e8 66 02 00 00 57 6a 6f 88 46 05 e8 5b 02 00 00 8a f0 57 88 76 06 6a 67 88 76 07 e8 4b 02 00 00 57 6a 6c 88 46 08 e8 40 02 00 00 57 8a e8 6a 65 } //2
		$a_01_2 = {6a 44 e8 4c 01 00 00 6a 50 88 01 e8 43 01 00 00 6a 53 88 41 01 e8 39 01 00 00 6a 54 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=5
 
}