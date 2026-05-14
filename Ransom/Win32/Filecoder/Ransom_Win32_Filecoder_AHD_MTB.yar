
rule Ransom_Win32_Filecoder_AHD_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffff96 00 ffffff96 00 05 00 00 "
		
	strings :
		$a_81_0 = {70 69 6e 67 20 31 32 37 2e 32 20 2d 6e 20 31 30 20 26 20 63 64 2f 20 26 20 65 63 68 6f 28 7c 22 25 73 22 20 2d 2d 64 69 73 61 62 6c 65 20 26 20 72 64 20 2f 71 20 2f 73 20 22 25 73 } //10 ping 127.2 -n 10 & cd/ & echo(|"%s" --disable & rd /q /s "%s
		$a_81_1 = {50 41 59 32 4b 45 59 5f 4c 4f 47 2e 74 78 74 } //20 PAY2KEY_LOG.txt
		$a_81_2 = {2d 65 20 77 61 74 63 68 20 2d 70 69 64 } //30 -e watch -pid
		$a_81_3 = {5b 2a 5d 20 57 6f 72 6b 20 66 69 6e 69 73 68 65 64 } //40 [*] Work finished
		$a_81_4 = {5b 2a 5d 20 53 63 61 6e 20 68 6f 73 74 73 20 73 74 61 72 74 65 64 20 61 74 3a 20 25 73 } //50 [*] Scan hosts started at: %s
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*20+(#a_81_2  & 1)*30+(#a_81_3  & 1)*40+(#a_81_4  & 1)*50) >=150
 
}