
rule Trojan_Win32_GuLoader_RBB_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {23 5c 69 6d 70 72 67 6e 65 72 69 6e 67 65 72 5c 42 6f 74 69 6c 6c 61 5c 68 6a 6c 70 65 66 69 6c 65 6e 73 } //1 #\imprgneringer\Botilla\hjlpefilens
		$a_81_1 = {71 75 61 72 74 65 72 6c 61 6e 64 } //1 quarterland
		$a_81_2 = {67 61 73 74 72 6f 70 68 69 6c 75 73 20 74 69 6d 65 66 6f 72 62 72 75 67 65 6e 65 73 } //1 gastrophilus timeforbrugenes
		$a_81_3 = {73 74 65 70 72 65 6c 61 74 69 6f 6e 73 68 69 70 } //1 steprelationship
		$a_81_4 = {67 72 75 6e 64 6c 6f 76 73 74 61 6c 65 6e 73 20 72 65 64 68 61 6e 64 65 64 6e 65 73 73 2e 65 78 65 } //1 grundlovstalens redhandedness.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win32_GuLoader_RBB_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {4d 69 6c 69 65 75 62 65 73 6b 79 74 74 65 6c 73 65 73 73 65 6b 74 6f 72 65 72 5c 41 63 65 74 79 6c 65 6e 65 } //1 Milieubeskyttelsessektorer\Acetylene
		$a_81_1 = {74 73 5c 65 6b 73 74 72 61 66 6f 72 74 6a 65 6e 65 73 74 65 73 2e 52 6b 65 } //1 ts\ekstrafortjenestes.Rke
		$a_81_2 = {25 73 69 74 72 65 25 5c 73 69 64 73 65 72 73 2e 41 64 72 } //1 %sitre%\sidsers.Adr
		$a_81_3 = {73 6d 69 74 73 6f 6d 6d 65 73 74 65 20 72 64 6c 65 72 65 74 73 } //1 smitsommeste rdlerets
		$a_81_4 = {6d 6f 6e 6f 6e 69 74 72 69 64 65 20 66 69 73 6b 65 6b 75 74 74 65 72 20 69 6e 6a 65 63 74 73 } //1 mononitride fiskekutter injects
		$a_81_5 = {76 6f 63 6f 64 65 64 20 64 69 66 66 65 72 65 6e 74 69 65 72 69 6e 67 65 72 2e 65 78 65 } //1 vocoded differentieringer.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}