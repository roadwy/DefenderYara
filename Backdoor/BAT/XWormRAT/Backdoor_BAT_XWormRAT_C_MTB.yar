
rule Backdoor_BAT_XWormRAT_C_MTB{
	meta:
		description = "Backdoor:BAT/XWormRAT.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 00 04 20 e8 03 00 00 d8 28 } //2
		$a_01_1 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
		$a_01_2 = {73 65 74 5f 45 78 70 65 63 74 31 30 30 43 6f 6e 74 69 6e 75 65 } //1 set_Expect100Continue
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}