
rule Trojan_Win32_Padop_A{
	meta:
		description = "Trojan:Win32/Padop.A,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 00 65 00 6e 00 64 00 70 00 6f 00 70 00 75 00 70 00 3d 00 4e 00 31 00 39 00 } //10 sendpopup=N19
		$a_01_1 = {74 00 72 00 61 00 63 00 65 00 6d 00 79 00 69 00 70 00 2e 00 6f 00 72 00 67 00 2f 00 } //1 tracemyip.org/
		$a_01_2 = {77 00 73 00 20 00 52 00 65 00 73 00 74 00 6f 00 72 00 65 00 5c 00 6e 00 75 00 6d 00 2e 00 74 00 78 00 74 00 } //1 ws Restore\num.txt
		$a_01_3 = {61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 3b 00 20 00 6e 00 61 00 6d 00 65 00 3d 00 22 00 75 00 70 00 6c 00 6f 00 61 00 64 00 65 00 64 00 22 00 } //1 attachment; name="uploaded"
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}