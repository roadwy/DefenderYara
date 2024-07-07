
rule Trojan_Win32_Sipoo_A{
	meta:
		description = "Trojan:Win32/Sipoo.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 01 58 39 44 24 08 7e 90 01 01 8b 4c 24 04 8a 54 08 ff 30 14 08 40 3b 44 24 08 7c 90 01 01 c3 90 00 } //1
		$a_03_1 = {ff 75 08 ff d6 01 45 0c 39 7d 0c 74 90 01 01 ff 45 10 83 7d 90 01 02 72 90 01 01 32 c0 eb 90 00 } //1
		$a_00_2 = {48 6f 73 74 4e 61 6d 65 3a 25 73 20 20 20 20 46 6c 61 67 3a 25 73 } //1 HostName:%s    Flag:%s
		$a_00_3 = {42 61 63 6b 54 69 6d 65 3a 25 73 } //1 BackTime:%s
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}