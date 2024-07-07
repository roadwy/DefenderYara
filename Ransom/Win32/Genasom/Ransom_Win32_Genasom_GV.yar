
rule Ransom_Win32_Genasom_GV{
	meta:
		description = "Ransom:Win32/Genasom.GV,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 f8 10 75 09 80 3d 90 01 04 30 74 13 8b c5 8d 50 01 8a 08 40 3a cb 75 f9 2b c2 83 f8 13 75 0a 6a 40 90 00 } //5
		$a_01_1 = {70 61 79 6d 65 6e 74 20 76 61 6c 69 64 61 74 69 6f 6e 20 77 69 6c 6c 20 74 61 6b 65 20 61 70 70 72 6f 78 69 6d 61 74 65 6c 79 20 32 2d 34 20 68 6f 75 72 73 20 62 65 66 6f 72 65 20 79 6f 75 20 77 69 6c 6c 20 67 65 74 20 61 63 63 65 73 73 20 74 6f 20 79 6f 75 72 20 73 79 73 74 65 6d } //1 payment validation will take approximately 2-4 hours before you will get access to your system
		$a_01_2 = {53 69 6c 65 6e 63 65 5f 6c 6f 63 6b 5f 62 6f 74 2e 70 64 62 } //1 Silence_lock_bot.pdb
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}