
rule Trojan_Win32_DllHijack_C_MTB{
	meta:
		description = "Trojan:Win32/DllHijack.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a c1 32 c3 34 36 8a d8 41 88 1e 3b 8d } //3
		$a_01_1 = {52 55 4e 41 53 41 44 4d 49 4e } //2 RUNASADMIN
		$a_01_2 = {2f 75 61 63 } //2 /uac
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=7
 
}