
rule Trojan_WinNT_Koutodoor_E{
	meta:
		description = "Trojan:WinNT/Koutodoor.E,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_08_0 = {65 00 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 73 00 } //2 etc\hosts
		$a_08_1 = {5c 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 72 00 75 00 6e 00 6f 00 6e 00 63 00 65 00 } //2 \registry\machine\software\microsoft\windows\currentversion\runonce
		$a_02_2 = {56 56 56 6a 01 8d 45 f4 6a 0f 50 56 56 56 ff 75 fc ff 15 ?? ?? ?? ?? 85 c0 } //1
		$a_00_3 = {55 8b ec 51 50 0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0 58 8b 45 08 8b 4d fc 89 08 c9 c2 04 00 } //2
		$a_03_4 = {99 f7 7d 0c 8b 45 08 32 ?? 02 } //1
		$a_01_5 = {99 f7 7d 0c 8a 45 ff 32 04 0a } //1
	condition:
		((#a_08_0  & 1)*2+(#a_08_1  & 1)*2+(#a_02_2  & 1)*1+(#a_00_3  & 1)*2+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}