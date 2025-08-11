
rule Trojan_BAT_AsyncRAT_GZN_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.GZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {4b 69 6c 6c 53 79 73 74 65 6d 53 65 74 74 69 6e 67 73 50 72 6f 63 65 73 73 } //1 KillSystemSettingsProcess
		$a_01_1 = {5c 4e 6a 52 61 74 } //1 \NjRat
		$a_80_2 = {4b 69 6c 6c 53 77 69 74 63 68 } //KillSwitch  1
		$a_80_3 = {6b 69 6c 6c 69 6e 67 20 53 79 73 74 65 6d 53 65 74 74 69 6e 67 73 } //killing SystemSettings  1
		$a_80_4 = {54 61 73 6b 20 4b 69 6c 6c } //Task Kill  1
		$a_80_5 = {50 72 6f 63 65 73 73 20 48 61 63 6b 65 72 } //Process Hacker  1
		$a_80_6 = {48 69 6a 61 63 6b 43 6c 65 61 6e 65 72 36 34 } //HijackCleaner64  1
		$a_80_7 = {50 6f 77 65 72 53 68 65 6c 6c } //PowerShell  1
		$a_80_8 = {57 69 72 65 73 68 61 72 6b } //Wireshark  1
		$a_80_9 = {63 6f 6e 66 75 73 65 72 } //confuser  1
		$a_80_10 = {50 72 6f 63 6d 6f 6e } //Procmon  1
		$a_80_11 = {50 72 6f 63 65 73 73 20 45 78 70 6c 6f 72 65 72 } //Process Explorer  1
		$a_80_12 = {58 76 69 72 75 73 } //Xvirus  1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1) >=13
 
}