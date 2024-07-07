
rule Ransom_Win32_FileCoder_NC_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.NC!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 68 75 74 64 6f 77 6e 20 2d 73 20 2d 66 20 2d 74 } //1 shutdown -s -f -t
		$a_01_1 = {5c 44 65 73 6b 74 6f 70 5c 52 45 41 44 4d 45 2e 74 78 74 } //1 \Desktop\README.txt
		$a_01_2 = {5c 52 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62 } //1 \Ransomware.pdb
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}