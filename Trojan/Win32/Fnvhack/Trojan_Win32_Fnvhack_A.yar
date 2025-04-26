
rule Trojan_Win32_Fnvhack_A{
	meta:
		description = "Trojan:Win32/Fnvhack.A,SIGNATURE_TYPE_PEHSTR,15 00 15 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 00 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 00 00 4b 45 52 4e 45 4c 33 32 2e 64 6c 6c } //10
		$a_01_1 = {6a 4a 59 d9 ee d9 74 24 f4 58 81 70 13 fb ee 99 bc 83 e8 fc e2 f4 } //10
		$a_01_2 = {31 db 64 8b 43 30 8b 40 0c 8b 70 1c ad 8b 40 08 5e 68 8e 4e 0e ec 50 ff d6 } //1
		$a_01_3 = {8d 20 8a 12 ff cb 65 d9 b0 70 9e 85 11 70 ae 91 e2 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=21
 
}