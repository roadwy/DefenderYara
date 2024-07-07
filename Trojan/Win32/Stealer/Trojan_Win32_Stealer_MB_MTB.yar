
rule Trojan_Win32_Stealer_MB_MTB{
	meta:
		description = "Trojan:Win32/Stealer.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {e1 30 0d 31 61 31 9a 31 c1 31 ed 31 5c 32 68 32 8e 32 ad 32 ce 32 06 33 25 34 31 34 49 34 6a 34 } //10
		$a_01_1 = {77 69 6e 64 6f 77 73 5c 53 79 73 57 4f 57 36 34 5c 52 77 79 6d 6f 75 64 6c 65 } //1 windows\SysWOW64\Rwymoudle
		$a_01_2 = {70 65 72 6d 69 73 73 69 6f 6e 20 64 65 6e 69 65 64 } //1 permission denied
		$a_01_3 = {6e 65 74 77 6f 72 6b 5f 64 6f 77 6e } //1 network_down
		$a_01_4 = {6e 6f 74 20 61 20 73 6f 63 6b 65 74 } //1 not a socket
		$a_01_5 = {47 65 74 43 6f 6d 70 75 74 65 72 4e 61 6d 65 41 } //1 GetComputerNameA
		$a_01_6 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}