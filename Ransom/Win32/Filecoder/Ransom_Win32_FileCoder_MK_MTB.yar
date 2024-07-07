
rule Ransom_Win32_FileCoder_MK_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {43 6f 76 69 64 36 36 36 2e 62 61 74 } //1 Covid666.bat
		$a_81_1 = {41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } //1 ALL YOUR FILES ARE ENCRYPTED
		$a_81_2 = {4f 6e 6c 79 20 77 61 79 20 74 6f 20 67 65 74 20 74 68 65 6d 20 62 61 63 6b 20 69 73 20 74 6f 20 70 61 79 20 31 30 30 30 24 20 77 6f 72 74 68 20 6f 66 20 42 54 43 } //1 Only way to get them back is to pay 1000$ worth of BTC
		$a_81_3 = {59 6f 75 20 62 65 63 61 6d 65 20 61 20 76 69 63 74 69 6d 20 6f 66 20 74 68 65 20 43 6f 76 69 64 2d 36 36 36 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 You became a victim of the Covid-666 Ransomware
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}