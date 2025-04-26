
rule Trojan_Win32_Drixed_QE_MTB{
	meta:
		description = "Trojan:Win32/Drixed.QE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {78 6d 72 69 67 } //xmrig  3
		$a_80_1 = {70 6f 77 72 70 72 6f 66 2e 64 6c 6c } //powrprof.dll  3
		$a_80_2 = {50 6f 77 65 72 52 65 67 69 73 74 65 72 53 75 73 70 65 6e 64 52 65 73 75 6d 65 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //PowerRegisterSuspendResumeNotification  3
		$a_80_3 = {49 6e 76 6f 6b 65 4d 61 69 6e 56 69 61 43 52 54 } //InvokeMainViaCRT  3
		$a_80_4 = {47 65 74 41 64 61 70 74 65 72 73 41 64 64 72 65 73 73 65 73 } //GetAdaptersAddresses  3
		$a_80_5 = {4c 6f 6f 6b 75 70 50 72 69 76 69 6c 65 67 65 56 61 6c 75 65 57 } //LookupPrivilegeValueW  3
		$a_80_6 = {57 53 41 53 6f 63 6b 65 74 57 } //WSASocketW  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}