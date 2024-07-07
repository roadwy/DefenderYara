
rule Ransom_MSIL_Filecoder_A{
	meta:
		description = "Ransom:MSIL/Filecoder.A,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 64 65 6e 6e 69 73 5c 44 65 73 6b 74 6f 70 5c 53 6f 66 74 77 61 72 65 5c 42 53 53 5f 72 61 6e 73 6f 6d 77 61 72 65 5c 42 53 53 5f 72 61 6e 73 6f 6d 77 61 72 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 42 53 53 5f 72 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62 } //5 C:\Users\dennis\Desktop\Software\BSS_ransomware\BSS_ransomware\obj\Debug\BSS_ransomware.pdb
		$a_01_1 = {53 00 65 00 6e 00 64 00 20 00 6d 00 65 00 20 00 73 00 6f 00 6d 00 65 00 20 00 62 00 69 00 74 00 63 00 6f 00 69 00 6e 00 73 00 20 00 6f 00 72 00 20 00 6b 00 65 00 62 00 61 00 62 00 } //5 Send me some bitcoins or kebab
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}