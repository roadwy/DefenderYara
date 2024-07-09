
rule Ransom_Win32_MBRLocker_A_bit{
	meta:
		description = "Ransom:Win32/MBRLocker.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 5c 70 68 79 73 69 63 61 6c 64 72 69 76 65 30 } //10 \\.\\physicaldrive0
		$a_01_1 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 69 73 20 6c 6f 63 6b 65 64 } //10 Your computer is locked
		$a_01_2 = {77 77 65 31 30 30 } //3 wwe100
		$a_03_3 = {6a 00 6a 00 6a 00 56 ff 15 ?? ?? ?? ?? 6a 00 8d 45 f4 50 68 00 02 00 00 68 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 56 ff 15 } //2
		$a_01_4 = {32 54 05 f4 40 3b c1 7c f7 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*3+(#a_03_3  & 1)*2+(#a_01_4  & 1)*1) >=23
 
}