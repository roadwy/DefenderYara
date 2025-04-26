
rule Ransom_Win32_Filecoder_PI_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PI!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 } //1 SOFTWARE\Policies\Microsoft\Windows Defender
		$a_01_1 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //1 DisableAntiSpyware
		$a_01_2 = {73 76 68 6f 73 74 2e 65 78 65 } //1 svhost.exe
		$a_01_3 = {54 68 65 20 74 65 72 72 69 62 6c 65 20 76 69 72 75 73 20 68 61 73 20 63 61 70 74 75 72 65 64 20 79 6f 75 72 20 66 69 6c 65 73 } //1 The terrible virus has captured your files
		$a_01_4 = {43 3a 5c 44 65 63 6f 64 65 72 2e 68 74 61 } //1 C:\Decoder.hta
		$a_01_5 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 61 20 75 6e 69 71 75 65 20 49 44 } //1 Your files are encrypted a unique ID
		$a_01_6 = {54 68 69 73 20 77 69 6c 6c 20 69 6e 65 76 69 74 61 62 6c 79 20 6c 65 61 64 20 74 6f 20 70 65 72 6d 61 6e 65 6e 74 20 64 61 74 61 20 6c 6f 73 73 } //1 This will inevitably lead to permanent data loss
		$a_01_7 = {44 61 74 61 20 72 65 63 6f 76 65 72 79 2e 68 74 61 } //1 Data recovery.hta
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=5
 
}