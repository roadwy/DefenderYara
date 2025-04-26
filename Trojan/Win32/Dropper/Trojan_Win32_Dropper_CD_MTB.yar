
rule Trojan_Win32_Dropper_CD_MTB{
	meta:
		description = "Trojan:Win32/Dropper.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {32 c3 f8 d0 c8 f6 d8 d0 c0 fe c9 0f 93 c1 fe c0 32 d8 66 f7 d9 89 14 04 } //1
		$a_01_1 = {33 d9 03 f1 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}