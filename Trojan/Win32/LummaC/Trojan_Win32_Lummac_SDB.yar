
rule Trojan_Win32_Lummac_SDB{
	meta:
		description = "Trojan:Win32/Lummac.SDB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {62 75 79 20 6e 6f 77 3a 20 74 67 20 40 6c 75 6d 6d 61 6e 6f 77 6f 72 6b } //buy now: tg @lummanowork  1
		$a_80_1 = {62 75 79 26 73 65 6c 6c 20 6c 6f 67 73 3a 20 40 6c 75 6d 6d 61 6d 61 72 6b 65 74 70 6c 61 63 65 5f 62 6f 74 } //buy&sell logs: @lummamarketplace_bot  1
		$a_80_2 = {6c 75 6d 6d 61 63 32 20 62 75 69 6c 64 3a } //lummac2 build:  1
		$a_80_3 = {63 6f 6e 66 69 67 75 72 61 74 69 6f 6e 3a } //configuration:  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}