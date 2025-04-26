
rule Trojan_Win32_Killfiles_CX{
	meta:
		description = "Trojan:Win32/Killfiles.CX,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 25 73 79 73 74 65 6d 64 72 69 76 65 25 2a 2e ?? ?? ?? [0-10] 63 6f 6c 6f 72 20 31 66 [0-10] 54 69 74 6c 65 20 d5 e2 ca c7 b2 a1 b6 be 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}