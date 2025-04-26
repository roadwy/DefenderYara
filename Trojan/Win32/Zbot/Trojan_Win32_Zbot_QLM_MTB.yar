
rule Trojan_Win32_Zbot_QLM_MTB{
	meta:
		description = "Trojan:Win32/Zbot.QLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 62 65 73 74 68 6f 74 65 6c 33 36 30 2e 63 6f 6d 3a 31 32 31 39 2f 30 30 31 2f 70 75 70 70 65 74 2e 54 78 74 } //2 http://www.besthotel360.com:1219/001/puppet.Txt
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //2 VirtualProtect
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //2 VirtualAlloc
		$a_01_3 = {48 54 54 50 2f 31 2e 31 } //2 HTTP/1.1
		$a_01_4 = {48 54 54 50 2f 31 2e 30 } //2 HTTP/1.0
		$a_01_5 = {50 72 79 4a 45 4e 31 4d 68 31 69 46 59 50 72 79 4a 45 4e 31 4d 68 31 69 46 59 50 72 79 4a 45 4e 31 4d 68 31 69 46 59 } //2 PryJEN1Mh1iFYPryJEN1Mh1iFYPryJEN1Mh1iFY
		$a_01_6 = {44 43 57 36 4e 62 37 76 68 67 45 61 69 44 43 57 36 4e 62 37 76 68 67 45 61 69 44 43 57 36 4e 62 37 76 68 67 45 61 69 } //2 DCW6Nb7vhgEaiDCW6Nb7vhgEaiDCW6Nb7vhgEai
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=14
 
}