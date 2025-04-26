
rule Trojan_Win32_RasDialer{
	meta:
		description = "Trojan:Win32/RasDialer,SIGNATURE_TYPE_PEHSTR,0b 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 73 76 63 68 65 73 74 2e 69 6e 69 } //5 \svchest.ini
		$a_01_1 = {43 3a 5c 31 2e 74 6d 70 } //5 C:\1.tmp
		$a_01_2 = {48 4f 53 54 3d 30 31 36 31 2c 31 31 30 30 2c 6d 70 65 38 2f 37 36 35 } //1 HOST=0161,1100,mpe8/765
		$a_01_3 = {48 4f 53 54 3d 64 78 6a 75 2c 31 31 30 30 2c 6d 70 65 38 30 2e 2f 2e } //1 HOST=dxju,1100,mpe80./.
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=10
 
}