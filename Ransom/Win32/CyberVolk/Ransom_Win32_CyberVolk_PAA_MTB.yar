
rule Ransom_Win32_CyberVolk_PAA_MTB{
	meta:
		description = "Ransom:Win32/CyberVolk.PAA!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 79 62 65 72 56 6f 6c 6b 20 72 61 6e 73 6f 6d 77 61 72 65 } //5 CyberVolk ransomware
		$a_01_1 = {43 79 62 65 72 56 6f 6c 6b 5f 52 65 61 64 4d 65 2e 74 78 74 } //1 CyberVolk_ReadMe.txt
		$a_01_2 = {79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 your files have been encrypted
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}