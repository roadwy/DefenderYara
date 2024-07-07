
rule Ransom_Win32_WannaCrypt_B_rsm{
	meta:
		description = "Ransom:Win32/WannaCrypt.B!rsm,SIGNATURE_TYPE_PEHSTR_EXT,fffffff4 01 fffffff4 01 05 00 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 5c 4d 73 57 69 6e 5a 6f 6e 65 73 43 61 63 68 65 43 6f 75 6e 74 65 72 4d 75 74 65 78 41 } //100 Global\MsWinZonesCacheCounterMutexA
		$a_01_1 = {74 61 73 6b 73 63 68 65 2e 65 78 65 } //100 tasksche.exe
		$a_01_2 = {57 4e 63 72 79 40 32 6f 6c 37 } //100 WNcry@2ol7
		$a_01_3 = {74 2e 77 6e 72 79 } //100 t.wnry
		$a_01_4 = {54 61 73 6b 53 74 61 72 74 } //100 TaskStart
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100+(#a_01_4  & 1)*100) >=500
 
}
rule Ransom_Win32_WannaCrypt_B_rsm_2{
	meta:
		description = "Ransom:Win32/WannaCrypt.B!rsm,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 41 4e 4e 41 43 52 59 00 } //2
		$a_01_1 = {21 57 61 6e 6e 61 44 65 63 72 79 70 74 6f 72 21 2e 65 78 65 } //2 !WannaDecryptor!.exe
		$a_01_2 = {75 2e 77 72 79 00 00 00 25 2e 31 66 20 42 54 43 } //1
		$a_01_3 = {57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 3e 20 63 2e 76 62 73 } //1 WScript.CreateObject("WScript.Shell")> c.vbs
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}