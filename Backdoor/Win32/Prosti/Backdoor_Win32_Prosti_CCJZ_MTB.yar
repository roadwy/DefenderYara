
rule Backdoor_Win32_Prosti_CCJZ_MTB{
	meta:
		description = "Backdoor:Win32/Prosti.CCJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 20 54 6f 20 49 6e 4a 65 63 74 } //2 Start To InJect
		$a_01_1 = {44 6c 6c 72 75 6e } //2 Dllrun
		$a_01_2 = {42 75 66 5f 43 6f 6f 6c 44 6c 6c } //1 Buf_CoolDll
		$a_01_3 = {52 65 61 6c 48 6f 73 74 3a } //1 RealHost:
		$a_01_4 = {48 6f 73 74 50 49 44 3a } //1 HostPID:
		$a_01_5 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 4e 65 74 44 44 45 5c 53 79 73 44 6c 6c } //1 SYSTEM\CurrentControlSet\Services\NetDDE\SysDll
		$a_01_6 = {5c 54 65 6d 70 5c 63 6f 6d 62 2e 64 6c 6c } //1 \Temp\comb.dll
		$a_01_7 = {43 3a 5c 24 52 45 43 59 43 4c 45 2e 42 49 4e } //1 C:\$RECYCLE.BIN
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=10
 
}