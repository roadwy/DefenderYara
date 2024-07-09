
rule Trojan_Win32_RanumBot_MT_MTB{
	meta:
		description = "Trojan:Win32/RanumBot.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {41 75 74 68 65 6e 74 69 63 61 74 65 5a 61 6e 61 62 61 7a 61 72 5f 53 71 75 61 72 65 5c 77 69 6e 64 65 66 65 6e 64 65 72 2e 65 78 65 } //1 AuthenticateZanabazar_Square\windefender.exe
		$a_00_1 = {72 65 70 6f 72 74 2f 61 70 70 2f 76 63 2e 65 78 65 } //1 report/app/vc.exe
		$a_00_2 = {5c 57 69 6e 4d 6f 6e 5c 70 61 74 63 68 2e 65 78 65 } //1 \WinMon\patch.exe
		$a_02_3 = {46 69 6c 65 55 52 4c 20 73 74 72 69 6e 67 [0-09] 66 69 6c 65 5f 75 72 6c } //1
		$a_02_4 = {52 75 6e 41 73 54 49 20 62 6f 6f 6c [0-09] 72 75 6e 61 73 74 69 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}