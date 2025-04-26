
rule Trojan_Win32_Malagent_PAC_MTB{
	meta:
		description = "Trojan:Win32/Malagent.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 63 68 74 61 73 6b 73 2e 65 78 65 } //1 schtasks.exe
		$a_01_1 = {31 32 33 2e 32 35 33 2e 33 33 2e 32 31 31 } //1 123.253.33.211
		$a_01_2 = {52 65 63 6f 72 64 65 64 54 56 5c 52 65 63 6f 72 64 65 64 54 56 2e 45 58 45 } //1 RecordedTV\RecordedTV.EXE
		$a_01_3 = {2f 46 20 2f 43 72 65 61 74 65 20 2f 54 4e 20 4d 69 63 72 6f 73 6f 66 74 5f 43 6f 72 70 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 4d 4f 20 31 20 2f 54 52 } //1 /F /Create /TN Microsoft_Corp /sc minute /MO 1 /TR
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}