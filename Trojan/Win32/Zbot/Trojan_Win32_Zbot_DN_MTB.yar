
rule Trojan_Win32_Zbot_DN_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {bf f5 b2 36 f8 31 ee 55 28 3a 1a 5e 3f a3 b2 30 34 03 30 99 08 f3 f2 9d e1 f2 } //1
		$a_81_1 = {43 3a 5c 55 73 65 72 73 5c 46 72 61 6e 6b 5c 44 65 73 6b 74 6f 70 5c 6b 68 48 52 45 62 50 6a 2e 65 78 65 } //1 C:\Users\Frank\Desktop\khHREbPj.exe
		$a_81_2 = {43 3a 5c 55 73 65 72 73 5c 61 64 6d 69 6e 5c 44 6f 77 6e 6c 6f 61 64 73 5c 66 66 65 6e 67 68 2e 65 78 65 } //1 C:\Users\admin\Downloads\ffengh.exe
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}