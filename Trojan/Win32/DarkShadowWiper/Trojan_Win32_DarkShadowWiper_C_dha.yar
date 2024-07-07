
rule Trojan_Win32_DarkShadowWiper_C_dha{
	meta:
		description = "Trojan:Win32/DarkShadowWiper.C!dha,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 } //1 schtasks
		$a_00_1 = {2f 00 63 00 72 00 65 00 61 00 74 00 65 00 } //1 /create
		$a_01_2 = {43 00 72 00 61 00 73 00 68 00 48 00 61 00 6e 00 64 00 6c 00 65 00 72 00 55 00 41 00 43 00 } //1 CrashHandlerUAC
		$a_00_3 = {2f 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 } //65526 /disable
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*65526) >=3
 
}