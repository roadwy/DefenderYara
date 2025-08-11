
rule Trojan_Win64_Filecoder_AFD_MTB{
	meta:
		description = "Trojan:Win64/Filecoder.AFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 33 aa 48 39 c2 74 14 0f 1f 40 00 80 32 aa 80 72 01 aa 48 83 c2 02 48 39 c2 } //3
		$a_01_1 = {70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 76 6d 77 61 72 65 5c 76 6d 77 61 72 65 20 74 6f 6f 6c 73 5c 76 6d 74 6f 6f 6c 73 64 2e 65 78 65 } //2 program files\vmware\vmware tools\vmtoolsd.exe
		$a_01_2 = {70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 6f 72 61 63 6c 65 5c 76 69 72 74 75 61 6c 62 6f 78 20 67 75 65 73 74 20 61 64 64 69 74 69 6f 6e 73 5c 76 62 6f 78 73 65 72 76 69 63 65 2e 65 78 65 } //1 program files\oracle\virtualbox guest additions\vboxservice.exe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}