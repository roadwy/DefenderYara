
rule TrojanDropper_Win32_Rotbrow_F{
	meta:
		description = "TrojanDropper:Win32/Rotbrow.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 00 00 } //01 00 
		$a_01_1 = {43 6f 64 65 63 6f 6e 73 74 4f 6e 65 43 6c 69 63 6b 50 6c 75 67 69 6e 20 70 6c 75 67 69 6e 2e 00 } //01 00 
		$a_01_2 = {43 68 72 6f 6d 65 50 72 6f 74 65 63 74 69 6f 6e 45 6e 61 62 6c 65 64 00 } //01 00  桃潲敭牐瑯捥楴湯湅扡敬d
		$a_01_3 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 76 6e 64 2e 70 72 6f 74 65 63 74 6f 72 2e 73 65 74 74 69 6e 67 73 74 72 61 63 6b 65 72 } //00 00  application/x-vnd.protector.settingstracker
	condition:
		any of ($a_*)
 
}