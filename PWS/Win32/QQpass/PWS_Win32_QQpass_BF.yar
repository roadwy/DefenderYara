
rule PWS_Win32_QQpass_BF{
	meta:
		description = "PWS:Win32/QQpass.BF,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 51 51 } //01 00  Documents and Settings\Administrator\Application Data\QQ
		$a_00_1 = {6b 6a 6b 68 6a 68 67 00 25 64 00 00 5c 70 73 61 70 69 00 } //01 00 
		$a_00_2 = {73 74 61 74 69 63 00 00 66 73 66 00 31 32 34 34 00 00 00 00 51 51 } //01 00 
		$a_03_3 = {6a 64 ff d7 68 90 01 04 6a 00 ff d6 85 c0 a3 90 01 04 74 ea e8 90 01 02 ff ff 6a 00 6a 00 6a 00 68 90 01 02 00 10 6a 00 6a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}