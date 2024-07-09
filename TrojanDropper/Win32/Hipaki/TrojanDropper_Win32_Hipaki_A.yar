
rule TrojanDropper_Win32_Hipaki_A{
	meta:
		description = "TrojanDropper:Win32/Hipaki.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 2f 45 80 37 1b 80 37 45 f6 17 47 e2 f2 } //1
		$a_03_1 = {68 00 00 00 80 86 db 68 ?? ?? ?? ?? 86 db 68 ?? ?? ?? ?? 86 db 50 86 db c3 86 db a3 ?? ?? ?? ?? 86 db 83 f8 ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}