
rule Backdoor_Win32_Flibot{
	meta:
		description = "Backdoor:Win32/Flibot,SIGNATURE_TYPE_PEHSTR_EXT,12 00 0f 00 06 00 00 "
		
	strings :
		$a_00_0 = {50 00 49 00 4e 00 47 00 } //1 PING
		$a_00_1 = {50 00 4f 00 4e 00 47 00 } //1 PONG
		$a_00_2 = {4a 00 4f 00 49 00 4e 00 } //1 JOIN
		$a_00_3 = {46 00 4c 00 56 00 50 00 40 00 4a 00 4b 00 49 00 } //5 FLVP@JKI
		$a_03_4 = {66 33 45 d0 0f bf d0 52 ff 15 ?? ?? ?? ?? 8b d0 8d 4d c8 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b d0 8d 4d d4 ff 15 } //10
		$a_03_5 = {66 33 45 d0 0f bf c0 50 e8 ?? ?? ?? ?? 8b d0 8d 4d c8 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b d0 8d 4d d4 e8 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*5+(#a_03_4  & 1)*10+(#a_03_5  & 1)*10) >=15
 
}