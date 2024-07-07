
rule Trojan_Win32_Saycode{
	meta:
		description = "Trojan:Win32/Saycode,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 61 63 74 69 76 65 78 2f 73 61 79 63 6f 64 65 75 70 64 61 74 65 2e 69 6e 69 } //1 /activex/saycodeupdate.ini
		$a_01_1 = {5f 5f 53 43 53 57 50 41 43 4b 5f 53 43 52 55 4e 5f 4d 55 54 45 58 5f 5f } //1 __SCSWPACK_SCRUN_MUTEX__
		$a_01_2 = {73 68 65 6c 6c 65 78 70 2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 桳汥敬灸搮汬䐀汬敒楧瑳牥敓癲牥
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}