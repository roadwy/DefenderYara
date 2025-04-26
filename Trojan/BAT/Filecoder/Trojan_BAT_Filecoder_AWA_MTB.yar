
rule Trojan_BAT_Filecoder_AWA_MTB{
	meta:
		description = "Trojan:BAT/Filecoder.AWA!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {56 6f 69 64 43 72 79 70 74 20 65 6e 63 72 79 70 74 65 64 20 61 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 2e } //2 VoidCrypt encrypted all of your files.
		$a_01_1 = {54 68 65 72 65 20 69 73 20 6e 6f 20 77 61 79 20 74 6f 20 72 65 63 6f 76 65 72 20 61 6e 79 20 66 69 6c 65 73 2e } //2 There is no way to recover any files.
		$a_01_2 = {45 61 63 68 20 66 69 6c 65 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 75 73 69 6e 67 20 52 53 41 2e } //2 Each file has been encrypted using RSA.
		$a_01_3 = {54 68 65 72 65 20 69 73 20 6e 6f 74 68 69 6e 67 20 6c 65 66 74 20 6f 6e 20 79 6f 75 72 20 73 79 73 74 65 6d 20 65 78 63 65 70 74 20 74 68 65 20 4f 53 2e } //2 There is nothing left on your system except the OS.
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}