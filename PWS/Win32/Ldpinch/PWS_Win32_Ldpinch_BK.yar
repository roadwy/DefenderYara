
rule PWS_Win32_Ldpinch_BK{
	meta:
		description = "PWS:Win32/Ldpinch.BK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {75 bb 33 f6 56 68 80 00 00 00 6a 02 56 56 68 00 00 00 40 57 c7 80 ?? ?? ?? ?? 2e 6e 6c 73 } //3
		$a_01_1 = {05 20 07 00 00 50 6a 00 ff 75 08 } //1
		$a_01_2 = {2a 2a 52 65 74 43 6f 64 65 3a 20 00 } //1 ⨪敒䍴摯㩥 
		$a_01_3 = {68 74 74 70 73 65 6e 64 2e 64 6c 6c 00 49 45 43 6c 65 61 6e 55 70 00 49 45 49 6e 69 74 00 } //1 瑨灴敳摮搮汬䤀䍅敬湡灕䤀䥅楮t
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}