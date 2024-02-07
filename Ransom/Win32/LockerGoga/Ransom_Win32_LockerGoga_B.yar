
rule Ransom_Win32_LockerGoga_B{
	meta:
		description = "Ransom:Win32/LockerGoga.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {63 72 79 70 74 6f 2d 6c 6f 63 6b 65 72 5c 74 70 6c 73 5f 4d 53 56 43 5c 90 02 20 2f 65 78 63 65 70 74 69 6f 6e 2f 64 65 74 61 69 6c 2f 65 78 63 65 70 74 69 6f 6e 5f 70 74 72 2e 68 70 70 90 00 } //01 00 
		$a_00_1 = {28 00 64 00 6f 00 63 00 7c 00 64 00 6f 00 74 00 7c 00 77 00 62 00 6b 00 7c 00 64 00 6f 00 63 00 78 00 7c 00 64 00 6f 00 74 00 78 00 7c 00 64 00 6f 00 63 00 62 00 7c 00 78 00 6c 00 6d 00 7c 00 78 00 6c 00 73 00 78 00 7c 00 78 00 6c 00 74 00 78 00 7c 00 78 00 6c 00 73 00 62 00 7c 00 78 00 6c 00 77 00 7c 00 70 00 70 00 74 00 7c 00 70 00 6f 00 74 00 7c 00 70 00 70 00 73 00 7c 00 70 00 70 00 74 00 78 00 7c 00 70 00 6f 00 74 00 78 00 7c 00 70 00 70 00 73 00 78 00 7c 00 73 00 6c 00 64 00 78 00 7c 00 70 00 64 00 66 00 29 00 } //00 00  (doc|dot|wbk|docx|dotx|docb|xlm|xlsx|xltx|xlsb|xlw|ppt|pot|pps|pptx|potx|ppsx|sldx|pdf)
	condition:
		any of ($a_*)
 
}