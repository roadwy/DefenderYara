
rule Ransom_Win32_FileCoder_TX_MSR{
	meta:
		description = "Ransom:Win32/FileCoder.TX!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {21 54 58 44 4f 54 5f 52 45 41 44 5f 4d 45 21 2e 74 78 74 } //!TXDOT_READ_ME!.txt  1
		$a_80_1 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 73 65 63 75 72 65 6c 79 20 45 4e 43 52 59 50 54 45 44 } //Your files are securely ENCRYPTED  1
		$a_80_2 = {4d 61 69 6c 20 75 73 3a 20 74 78 64 6f 74 39 31 31 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //Mail us: txdot911@protonmail.com  1
		$a_80_3 = {73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } //set {default} recoveryenabled no  1
		$a_80_4 = {43 68 61 6e 67 65 20 2f 54 4e 20 22 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 52 65 73 74 6f 72 65 5c 53 52 22 20 2f 64 69 73 61 62 6c 65 } //Change /TN "\Microsoft\Windows\SystemRestore\SR" /disable  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}