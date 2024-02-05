
rule Ransom_Win32_FileCoder_MK_MSR{
	meta:
		description = "Ransom:Win32/FileCoder.MK!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {2f 63 20 74 69 6d 65 6f 75 74 20 31 20 26 26 20 64 65 6c 20 22 25 73 22 } ///c timeout 1 && del "%s"  02 00 
		$a_80_1 = {52 65 61 64 4d 65 2e 74 78 74 } //ReadMe.txt  04 00 
		$a_80_2 = {41 6c 6c 20 79 6f 75 72 20 64 61 74 61 20 62 65 65 6e 20 63 72 79 70 74 65 64 } //All your data been crypted  02 00 
		$a_80_3 = {7b 4b 45 59 31 31 31 31 31 7d } //{KEY11111}  02 00 
		$a_80_4 = {73 6f 64 69 6e 73 75 70 70 6f 72 74 40 63 6f 63 6b 2e 6c 69 } //sodinsupport@cock.li  00 00 
		$a_00_5 = {5d 04 00 00 2b 21 04 80 5c 27 } //00 00 
	condition:
		any of ($a_*)
 
}