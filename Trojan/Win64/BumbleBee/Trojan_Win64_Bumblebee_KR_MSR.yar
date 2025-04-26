
rule Trojan_Win64_Bumblebee_KR_MSR{
	meta:
		description = "Trojan:Win64/Bumblebee.KR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 65 51 77 79 53 64 4d } //2 CeQwySdM
		$a_01_1 = {4b 51 52 4e 37 31 } //2 KQRN71
		$a_01_2 = {4d 66 72 30 37 41 37 34 } //2 Mfr07A74
		$a_01_3 = {51 58 59 75 6f 6b 36 36 30 } //2 QXYuok660
		$a_01_4 = {70 76 75 6e 6a 53 6a 56 59 50 } //2 pvunjSjVYP
		$a_01_5 = {47 65 74 53 74 64 48 61 6e 64 6c 65 } //1 GetStdHandle
		$a_01_6 = {43 6f 6e 6e 65 63 74 4e 61 6d 65 64 50 69 70 65 } //1 ConnectNamedPipe
		$a_01_7 = {43 72 65 61 74 65 46 69 6c 65 57 } //1 CreateFileW
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=13
 
}