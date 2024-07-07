
rule Trojan_WinNT_Nagyo_A_rootkit{
	meta:
		description = "Trojan:WinNT/Nagyo.A!rootkit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 4d 0c 81 39 80 00 00 00 73 61 68 44 64 6b 20 8b 55 f8 52 6a 01 ff 15 90 01 04 8b 4d 0c 8b 11 8b 4d 08 89 04 91 8b 55 0c 8b 02 8b 4d 08 83 3c 81 00 75 0b 8b 55 14 c7 02 9a 00 00 c0 90 00 } //1
		$a_02_1 = {8b 48 04 81 79 18 73 45 72 76 75 0b 8b 55 cc 89 15 90 01 04 eb 05 e9 90 01 02 ff ff 83 3d 90 01 04 00 75 10 ff 15 90 01 04 b8 01 00 00 c0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}