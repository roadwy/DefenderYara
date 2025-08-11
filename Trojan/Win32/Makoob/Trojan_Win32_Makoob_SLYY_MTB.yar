
rule Trojan_Win32_Makoob_SLYY_MTB{
	meta:
		description = "Trojan:Win32/Makoob.SLYY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 00 6c 00 65 00 76 00 61 00 74 00 6f 00 72 00 74 00 72 00 75 00 63 00 6b 00 73 00 } //2 elevatortrucks
		$a_01_1 = {73 00 79 00 6e 00 64 00 65 00 62 00 75 00 6b 00 6b 00 65 00 6e 00 73 00 20 00 62 00 75 00 73 00 73 00 74 00 6f 00 70 00 70 00 65 00 73 00 74 00 65 00 64 00 65 00 74 00 73 00 } //2 syndebukkens busstoppestedets
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}