
rule Trojan_Win64_CryptInject_CM_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {32 84 0a e8 03 00 00 48 83 c1 01 48 8b 94 24 88 00 00 00 83 e1 0f 42 88 04 3a } //1
		$a_01_1 = {c1 e9 08 01 ca 88 50 02 89 d1 0f b6 50 01 c1 e9 08 01 ca 88 50 01 c1 ea 08 00 10 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_CryptInject_CM_MTB_2{
	meta:
		description = "Trojan:Win64/CryptInject.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {64 62 73 65 63 6b 65 79 3d } //1 dbseckey=
		$a_01_1 = {6c 6f 67 69 6e 2e 61 73 70 78 } //1 login.aspx
		$a_01_2 = {55 53 45 52 4e 41 4d 45 } //1 USERNAME
		$a_01_3 = {43 4f 4d 50 55 54 45 52 4e 41 4d 45 } //1 COMPUTERNAME
		$a_01_4 = {61 63 74 69 6f 6e 3d 70 69 6e 67 26 6d 6f 64 3d } //1 action=ping&mod=
		$a_01_5 = {55 73 65 72 2d 41 67 65 6e 74 3a } //1 User-Agent:
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}