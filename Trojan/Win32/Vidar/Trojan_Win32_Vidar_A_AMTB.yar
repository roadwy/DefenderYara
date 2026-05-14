
rule Trojan_Win32_Vidar_A_AMTB{
	meta:
		description = "Trojan:Win32/Vidar.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_81_0 = {6e 73 6c 6f 6f 6b 75 70 2e 65 78 65 20 2f 3f 6e 61 6a 73 68 75 33 30 38 66 61 67 73 38 33 } //2 nslookup.exe /?najshu308fags83
		$a_81_1 = {73 6c 75 74 20 62 69 6f 64 69 76 65 72 73 69 74 79 20 70 65 72 74 68 } //1 slut biodiversity perth
		$a_81_2 = {63 6d 64 20 2f 76 20 2f 63 20 53 65 74 20 55 6b 4f 4d 75 3d 63 6d 64 } //2 cmd /v /c Set UkOMu=cmd
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*2) >=5
 
}